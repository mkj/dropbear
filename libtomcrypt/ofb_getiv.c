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

#ifdef OFB

int ofb_getiv(unsigned char *IV, unsigned long *len, symmetric_OFB *ofb)
{
   _ARGCHK(IV  != NULL);
   _ARGCHK(len != NULL);
   _ARGCHK(ofb != NULL);
   if ((unsigned long)ofb->blocklen > *len) {
      return CRYPT_BUFFER_OVERFLOW;
   }
   memcpy(IV, ofb->IV, ofb->blocklen);
   *len = ofb->blocklen;

   return CRYPT_OK;
}

#endif
