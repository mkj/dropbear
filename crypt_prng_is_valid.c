/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://libtomcrypt.org
 */
#include "mycrypt.h"

int prng_is_valid(int idx)
{
   if (idx < 0 || idx >= TAB_SIZE || prng_descriptor[idx].name == NULL) {
      return CRYPT_INVALID_PRNG;
   }
   return CRYPT_OK;
}
