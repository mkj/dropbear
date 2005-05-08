/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */
#include "tomcrypt.h"

/**
  @file crypt_prng_is_valid.c
  Determine if PRNG is valid, Tom St Denis
*/

/*
   Test if a PRNG index is valid
   @param idx   The index of the PRNG to search for
   @return CRYPT_OK if valid
*/
int prng_is_valid(int idx)
{
   if (idx < 0 || idx >= TAB_SIZE || prng_descriptor[idx].name == NULL) {
      return CRYPT_INVALID_PRNG;
   }
   return CRYPT_OK;
}
