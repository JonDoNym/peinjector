/**
 * \file   libpeserver.h
 * \author A.G.
 * \brief  Provides PE patching functionality as server service
 */

#ifndef LIBPESERVER_H_
#define LIBPESERVER_H_

#include "libpeinfect.h"
#include "stdbool.h"
#include <pthread.h>
#include <semaphore.h>

/**
 * Debug output if set to true
 */
#define PESERVER_DEBUG_OUTPUT true

/**
 * Size of receive buffer for PE data port
 */
#define PESERVER_RECEIVE_BUFFER_PE 8192

/**
 * Size of receive buffer for control port
 */
#define PESERVER_RECEIVE_BUFFER_CONTROL 16384

/**
 * Size of connection queue for PE data port
 */
#define PESERVER_CONNECTION_QUEUE_PE 128

/**
 * Size of connection queue for control port
 */
#define PESERVER_CONNECTION_QUEUE_CONTROL 4

/**
 * Authentication token size
 */
#define PESERVER_TOKEN_SIZE 32

/**
 *  Size of Authentication magic
 */
#define PESERVER_TOKEN_MAGIC_SIZE 2

/**
 *  Authentication Magic
 */
#define PESERVER_TOKEN_MAGIC "\xAA\xAA"

/**
 * PECONFIG control struct
 */
typedef struct _PECONFIG {
  char *config_name;                   //!< Name of config file
  char *shellcode_x86_name;            //!< Name of x86 payload binary
  char *shellcode_x64_name;            //!< Name of x64 payload binary
  pthread_mutex_t config_mutex;        //!< Protecting mutex for config file
  pthread_mutex_t shellcode_x86_mutex; //!< Protecting mutex for x86 payload binary
  pthread_mutex_t shellcode_x64_mutex; //!< Protecting mutex for x64 payload binary
} PECONFIG;

/**
 * PESERVER control struct
 */
typedef struct _PESERVER {
  PEINFECT *infect;                   //!< PEINFECT structure used by servers
  int control_sock;                   //!< Control socket
  size_t control_port;                //!< Control port
  int data_sock;                      //!< Data socket
  size_t data_port;                   //!< Data port
  bool terminating;                   //!< Server terminates
  bool restart;                       //!< Restart flag for termination
  size_t watchers;                    //!< Number of Threads waiting for termination
  pthread_mutex_t mutex;              //!< Protecting lock
  sem_t signal;                       //!< Signalizes Termination
  bool enable_infection;              //!< Global enable flag
  bool persistent_ports;              //!< Can't change ports via control interface
  uint8_t token[PESERVER_TOKEN_SIZE]; //!< Authentication token
  PECONFIG *config;                   //!< PECONFIG configuration
# ifdef PESERVER_DEBUG_OUTPUT
  pthread_mutex_t debug_mutex;        //!< Debug output Protecting lock
# endif
} PESERVER;

/**
 * Tries to launch an PE Infector Server
 *
 * \param infect        PEINFECT config to use
 * \param configuration PECONTROL configuration
 * \param server        PESERVER control
 *
 * \return true on success, false otherwise
 */
bool peserver_init(PEINFECT *infect, PECONFIG *configuration, PESERVER *server);

/**
 * Initializes PECONFIG structure
 *
 * \param config_name        Name of config file
 * \param shellcode_x86_name Name of x86 shellcode binary
 * \param shellcode_x64_name Name of x64 shellcode binary
 *
 * \return true on success, false otherwise
 */
bool peserver_init_config(char *config_name, char *shellcode_x86_name, char *shellcode_x64_name, PECONFIG *out);

/**
 * Writes config to specified file
 *
 * \see peserver_init
 *
 * \param server PESERVER to write config for
 *
 */
void peserver_write_config(PESERVER *server);

/**
 * Returns pointer to access token
 *
 * \param server PESERVER to read token
 *
 * \return Token
 */
unsigned char* peserver_get_token(PESERVER *server);

/**
 * Set server access token
 *
 * \param token     Pointer to token. NULL will reset token to default
 * \param tokensize Size of token (Must match PESERVER_TOKEN_SIZE)
 * \param server    PESERVER to set token
 *
 * \return true on success, false otherwise
 */
bool peserver_set_token(unsigned char *token, size_t tokensize, PESERVER *server);

/**
 * Frees PECONFIG structure
 *
 * \param out PECONFIG structure to free
 *
 */
void peserver_free_config(PECONFIG *out);

/**
 * Waits until the given PE Infector Server terminates
 *
 * \param server PESERVER to wait for
 *
 * \return true if restart flag was set, false if not
 */
bool peserver_wait(PESERVER *server);

/**
 * Terminates the given PE Infector Server
 *
 * \param restart Sets restart flag if true
 * \param server  PESERVER to terminate
 *
 */
void peserver_terminate(bool restart, PESERVER *server);

/**
 * Enables infection globally
 *
 * \param enable If false infection is disables, enabled otherwise
 * \param server PESERVER to enable/disable infection functionality
 *
 */
void peserver_enable_infection(bool enable, PESERVER *server);

/**
 * Frees the resources of an PE Infector Server
 * (Make sure to call peserver_terminate() somewhere)
 *
 * \param server PESERVER to free
 *
 */
void peserver_free(PESERVER *server);

#endif /* LIBPESERVER_H_ */
