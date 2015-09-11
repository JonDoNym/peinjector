/**
 * \file   libpeprotocol.h
 * \author A.G.
 * \brief
 */

#ifndef LIBPEPROTOCOL_H_
#define LIBPEPROTOCOL_H_

#include "libpeinfect.h"
#include "libpeserver.h"
#include <stdbool.h>
#include <pthread.h>

/**
 * Processes PE Control Protocol data
 *
 * \param server      PESERVER where the data was received
 * \param sock        Socket where the data was received
 * \param datamem     Received data
 * \param datamemsize Size of received data
 *
 * \return false
 */
bool peprotocol_process_data(PESERVER *server, int sock, unsigned char *datamem, size_t datamemsize);

#endif /* LIBPEPROTOCOL_H_ */

