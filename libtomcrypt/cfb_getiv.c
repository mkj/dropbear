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

#ifdef CFB

int cfb_getiv(unsigned char *IV, unsigned long *len, symmetric_CFB *cfb)
{
   _ARGCHK(IV  != NULL);
   _ARGCHK(len != NULL);
   _ARGCHK(cfb != NULL);
   if ((unsigned long)cfb->blocklen > *len) {
      return CRYPT_BUFFER_OVERFLOW;
   }
   memcpy(IV, cfb->IV, cfb->blocklen);
   *len = cfb->blocklen;

   return CRYPT_OK;
}

#endif
