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

#ifdef CTR

int ctr_getiv(unsigned char *IV, unsigned long *len, symmetric_CTR *ctr)
{
   _ARGCHK(IV  != NULL);
   _ARGCHK(len != NULL);
   _ARGCHK(ctr != NULL);
   if ((unsigned long)ctr->blocklen > *len) {
      return CRYPT_BUFFER_OVERFLOW;
   }
   memcpy(IV, ctr->ctr, ctr->blocklen);
   *len = ctr->blocklen;

   return CRYPT_OK;
}

#endif
