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

int ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CTR *ctr)
{
   int x, err;

   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);
   _ARGCHK(ctr != NULL);

   if ((err = cipher_is_valid(ctr->cipher)) != CRYPT_OK) {
       return err;
   }
   
   /* is blocklen/padlen valid? */
   if (ctr->blocklen < 0 || ctr->blocklen > (int)sizeof(ctr->ctr) ||
       ctr->padlen   < 0 || ctr->padlen   > (int)sizeof(ctr->pad)) {
      return CRYPT_INVALID_ARG;
   }

   while (len-- > 0) {
      /* is the pad empty? */
      if (ctr->padlen == ctr->blocklen) {
         /* increment counter */
         if (ctr->mode == 0) {
            /* little-endian */
            for (x = 0; x < ctr->blocklen; x++) {
               ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
               if (ctr->ctr[x] != (unsigned char)0) {
                  break;
               }
            }
         } else {
            /* big-endian */
            for (x = ctr->blocklen-1; x >= 0; x--) {
               ctr->ctr[x] = (ctr->ctr[x] + (unsigned char)1) & (unsigned char)255;
               if (ctr->ctr[x] != (unsigned char)0) {
                  break;
               }
            }
         }

         /* encrypt it */
         cipher_descriptor[ctr->cipher].ecb_encrypt(ctr->ctr, ctr->pad, &ctr->key);
         ctr->padlen = 0;
      }
      *ct++ = *pt++ ^ ctr->pad[ctr->padlen++];
   }
   return CRYPT_OK;
}

#endif
