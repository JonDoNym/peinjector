/**
 * \file   libpepatch.h
 * \author A.A.
 * \brief  Deserializes and applies patches on stream data
 */

#ifndef CONNECTORS_LIBPEPATCH_H_
#define CONNECTORS_LIBPEPATCH_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Sentinel size of serialized patch
 */
#define PEPATCH_SENTINELSIZE 9

/**
 * PEPATCH structure
 */
typedef struct _PEPATCH {
  unsigned char *mem;    //!< Pointer to memory of current patch part
  size_t memsize;        //!< Size of current patch part
  size_t position;       //!< Position of current patch part
  bool insert;           //!< If true patch will be inserted, overwritten otherwise
  struct _PEPATCH *next; //!< Pointer to next patch part
  bool finished;         //!< Patch part fully applied
} PEPATCH;


/**
 * Tries to load a patch from serialized data
 *
 * \param mem     Imput memory
 * \param memsize Size of memory
 * \param out     Output PEPATCH
 *
 * \return true on success, false otherwise
 */
bool pepatch_load(unsigned char *mem, size_t memsize, PEPATCH *out);

/**
 * Tries to apply an patch onto a given memory stream part
 *
 * \param in       Input PEPATCH
 * \param mem      Memory to patch
 * \param memsize  Size of memory
 * \param position Postion of memory in stream
 *
 * \return true on success, false otherwise
 */
bool pepatch_apply(PEPATCH *in, unsigned char **mem, size_t *memsize, size_t position);

/**
 * Clears PEPATCH structure
 *
 * \param in Input PEPATCH structure
 */
void pepatch_free(PEPATCH *in);

#endif /* CONNECTORS_LIBPEPATCH_H_ */
