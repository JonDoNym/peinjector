/*
 * \file   libpepatch.c
 * \author A.A.
 * \brief  Deserializes and applies patches on stream data
 */

#include <stdlib.h>
#include <string.h>
#include "libpepatch.h"

/* Min/Max Macros */
#define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))

/* Adds new patch part */
static inline PEPATCH *__peinfect_add_patch_part(PEPATCH *parent) {
  PEPATCH *new_patch = calloc(1, sizeof(PEPATCH));
  parent->next = new_patch;

  return new_patch;
}

/* Add memory patch part */
static inline PEPATCH *__peinfect_add_patch_memory(PEPATCH *parent, void *mem, size_t memsize, size_t position,
bool insert) {
  parent->position = position;
  parent->memsize = memsize;
  parent->mem = malloc(parent->memsize);
  parent->insert = insert;

  /* Couldn't allocate memory */
  if (parent->mem == NULL) {
    return NULL;
  }

  /* Copy patch memory*/
  memcpy(parent->mem, mem, parent->memsize);

  /* Return next part*/
  return __peinfect_add_patch_part(parent);
}

bool pepatch_load(unsigned char *mem, size_t memsize, PEPATCH *out) {
  uint32_t *patch_memsize = (uint32_t *) mem;
  uint32_t total_partsize;
  PEPATCH *current = out;

  /* Memory buffer to small */
  if (memsize < (2 * sizeof(uint32_t) + sizeof(uint8_t))) {
    return false;
  }

  while (memsize) {
    /* Total size of serialized patch part */
    total_partsize = 2 * sizeof(uint32_t) + sizeof(uint8_t) + *patch_memsize;
    if (memsize >= total_partsize) {

      /* Sentinel patch part == 0*/
      if (*patch_memsize > 0) {
        /* Add patch part */
        current = __peinfect_add_patch_memory(current, mem + 2 * sizeof(uint32_t) + sizeof(uint8_t), *patch_memsize,
            *(uint32_t *) (mem + sizeof(uint32_t)), *(uint8_t *) (mem + 2 * sizeof(uint32_t)));

        /* Couldn't add patch part */
        if (current == NULL) {
          pepatch_free(out);
          return false;
        }
      }

      /* Adjust memory and memsize */
      mem += total_partsize;
      patch_memsize = (uint32_t *) mem;
      memsize -= total_partsize;

    } else {
      /* Invalid patch memory */
      pepatch_free(out);
      return false;

    }
  }

  return true;
}

bool pepatch_apply(PEPATCH *in, unsigned char **mem, size_t *memsize, size_t position) {
  PEPATCH *current = in;
  size_t delta_position;
  bool all_finished = true;

  /* No need to patch anything */
  if (mem == NULL || *mem == NULL || in->memsize == 0) {
    return true;
  }

  /* For each patch part */
  while (current) {

    /* Finished, no need to check */
    if (current->finished) {
      current = current->next;
      continue;
    }

    /* start position of current patch part in stream memory */
    if ((current->position >= position) && (current->position < position + *memsize)) {
      /* delta memory position */
      delta_position = current->position - position;

      /* insert memory */
      if (current->insert) {
        *mem = realloc(*mem, *memsize + current->memsize);
        if (*mem == NULL) {
          return false;
        }
        /* move memory */
        memmove(*mem + delta_position + current->memsize, *mem + delta_position, *memsize - delta_position);
        /* copy patch memory */
        memcpy(*mem + delta_position, current->mem, current->memsize);
        /* new mem size */
        *memsize += current->memsize;

        /* Patch finished */
        current->finished = true;

        /* overwrite */
      } else {
        memcpy(*mem + delta_position, current->mem, MIN(current->memsize, *memsize - delta_position));
      }

      /* Patch applied */
      all_finished = false;

      /* Append after current mem part (important if current part is the last part) */
    } else if (current->insert && (current->position == (position + *memsize))) {
      /* Insert at the end */
      *mem = realloc(*mem, *memsize + current->memsize);
      if (*mem == NULL) {
        return false;
      }
      /* copy patch memory */
      memcpy(*mem + *memsize, current->mem, current->memsize);
      /* new mem size */
      *memsize += current->memsize;

      /* Patch finished */
      current->finished = true;

      /* Patch applied */
      all_finished = false;

      /* end position of current patch part in stream memory or patch part bigger than stream memory */
    } else if (!current->insert && ((current->position + current->memsize) > position)
        && (current->position < position)) {
      /* delta memory position */
      delta_position = position - current->position;
      /* overwrite */
      memcpy(*mem, current->mem + delta_position, MIN(current->memsize - delta_position, *memsize));

      /* Patch applied */
      all_finished = false;

      /* Patch finished */
    } else if ((current->position + current->memsize) < position) {
      current->finished = true;

      /* Patch waiting, reset total finished  */
    } else {
      all_finished = false;
    }

    /* select next part */
    current = current->next;
  }

  /* Patch finished */
  if (all_finished) {
    in->memsize = 0;
  }

  return true;
}

void pepatch_free(PEPATCH *in) {
  PEPATCH *current = in;

  while (current != NULL) {
    /* Free memory */
    if (current->mem != NULL) {
      free(current->mem);
    }

    /* Free element if not first element*/
    if (current != in) {
      free(current);
    }

    /* Next element */
    current = current->next;
  }
}
