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

#ifdef CBC

int cbc_getiv(unsigned char *IV, unsigned long *len, symmetric_CBC *cbc)
{
   _ARGCHK(IV  != NULL);
   _ARGCHK(len != NULL);
   _ARGCHK(cbc != NULL);
   if ((unsigned long)cbc->blocklen > *len) {
      return CRYPT_BUFFER_OVERFLOW;
   }
   memcpy(IV, cbc->IV, cbc->blocklen);
   *len = cbc->blocklen;

   return CRYPT_OK;
}

#endif
