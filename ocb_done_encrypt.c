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

/* OCB Implementation by Tom St Denis */
#include "mycrypt.h"

#ifdef OCB_MODE

int ocb_done_encrypt(ocb_state *ocb, const unsigned char *pt, unsigned long ptlen,
                     unsigned char *ct, unsigned char *tag, unsigned long *taglen)
{
   _ARGCHK(ocb    != NULL);
   _ARGCHK(pt     != NULL);
   _ARGCHK(ct     != NULL);
   _ARGCHK(tag    != NULL);
   _ARGCHK(taglen != NULL);
   return __ocb_done(ocb, pt, ptlen, ct, tag, taglen, 0);
}

#endif

