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

int ofb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_OFB *ofb)
{
   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);
   _ARGCHK(ofb != NULL);
   return ofb_encrypt(ct, pt, len, ofb);
}


#endif

 
