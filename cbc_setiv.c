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

int cbc_setiv(const unsigned char *IV, unsigned long len, symmetric_CBC *cbc)
{
   _ARGCHK(IV  != NULL);
   _ARGCHK(cbc != NULL);
   if (len != (unsigned long)cbc->blocklen) {
      return CRYPT_INVALID_ARG;
   }
   XMEMCPY(cbc->IV, IV, len);
   return CRYPT_OK;
}

#endif 

