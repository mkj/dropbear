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

int ocb_decrypt_verify_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  
    const unsigned char *ct,     unsigned long ctlen,
          unsigned char *pt,
    const unsigned char *tag,    unsigned long taglen,
          int           *res)
{
   int err;
   ocb_state *ocb;

   _ARGCHK(key    != NULL);
   _ARGCHK(nonce  != NULL);
   _ARGCHK(pt     != NULL);
   _ARGCHK(ct     != NULL);
   _ARGCHK(tag    != NULL);
   _ARGCHK(res    != NULL);

   /* allocate memory */
   ocb = XMALLOC(sizeof(ocb_state));
   if (ocb == NULL) {
      return CRYPT_MEM;
   }

   if ((err = ocb_init(ocb, cipher, key, keylen, nonce)) != CRYPT_OK) {
      goto __ERR; 
   }

   while (ctlen > (unsigned long)ocb->block_len) {
        if ((err = ocb_decrypt(ocb, ct, pt)) != CRYPT_OK) {
            goto __ERR; 
        }
        ctlen   -= ocb->block_len;
        pt      += ocb->block_len;
        ct      += ocb->block_len;
   }

   err = ocb_done_decrypt(ocb, ct, ctlen, pt, tag, taglen, res);
__ERR:
#ifdef CLEAN_STACK
   zeromem(ocb, sizeof(ocb_state));
#endif
 
   XFREE(ocb);

   return err;
}

#endif
