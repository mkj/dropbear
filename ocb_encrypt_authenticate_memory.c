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

int ocb_encrypt_authenticate_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  
    const unsigned char *pt,     unsigned long ptlen,
          unsigned char *ct,
          unsigned char *tag,    unsigned long *taglen)
{
   int err;
   ocb_state *ocb;

   _ARGCHK(key    != NULL);
   _ARGCHK(nonce  != NULL);
   _ARGCHK(pt     != NULL);
   _ARGCHK(ct     != NULL);
   _ARGCHK(tag    != NULL);
   _ARGCHK(taglen != NULL);

   /* allocate ram */
   ocb = XMALLOC(sizeof(ocb_state));
   if (ocb == NULL) {
      return CRYPT_MEM;
   }

   if ((err = ocb_init(ocb, cipher, key, keylen, nonce)) != CRYPT_OK) {
      goto __ERR;
   }

   while (ptlen > (unsigned long)ocb->block_len) {
        if ((err = ocb_encrypt(ocb, pt, ct)) != CRYPT_OK) {
           goto __ERR;
        }
        ptlen   -= ocb->block_len;
        pt      += ocb->block_len;
        ct      += ocb->block_len;
   }

   err = ocb_done_encrypt(ocb, pt, ptlen, ct, tag, taglen);
__ERR:
#ifdef CLEAN_STACK
   zeromem(ocb, sizeof(ocb_state));
#endif

   XFREE(ocb);

   return err;
}

#endif
