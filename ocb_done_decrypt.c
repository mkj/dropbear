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

int ocb_done_decrypt(ocb_state *ocb, 
                     const unsigned char *ct,  unsigned long ctlen,
                           unsigned char *pt, 
                     const unsigned char *tag, unsigned long taglen, int *res)
{
   int err;
   unsigned char *tagbuf;
   unsigned long tagbuflen;

   _ARGCHK(ocb != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);
   _ARGCHK(tag != NULL);
   _ARGCHK(res != NULL);

   /* default to failed */
   *res = 0;

   /* allocate memory */
   tagbuf = XMALLOC(MAXBLOCKSIZE);
   if (tagbuf == NULL) {
      return CRYPT_MEM;
   }

   tagbuflen = MAXBLOCKSIZE;
   if ((err = __ocb_done(ocb, ct, ctlen, pt, tagbuf, &tagbuflen, 1)) != CRYPT_OK) {
      goto __ERR;
   }

   if (taglen <= tagbuflen && memcmp(tagbuf, tag, taglen) == 0) {
      *res = 1;
   }

   err = CRYPT_OK;
__ERR:
#ifdef CLEAN_STACK
   zeromem(tagbuf, MAXBLOCKSIZE);
#endif

   XFREE(tagbuf);

   return err;
}

#endif

