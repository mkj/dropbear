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

int cbc_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_CBC *cbc)
{
   int x, err;
   unsigned char tmp[MAXBLOCKSIZE], tmp2[MAXBLOCKSIZE];

   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);
   _ARGCHK(cbc != NULL);

   /* decrypt the block from ct into tmp */
   if ((err = cipher_is_valid(cbc->cipher)) != CRYPT_OK) {
       return err;
   }
   _ARGCHK(cipher_descriptor[cbc->cipher].ecb_decrypt != NULL);
      
   /* is blocklen valid? */
   if (cbc->blocklen < 0 || cbc->blocklen > (int)sizeof(cbc->IV)) {
      return CRYPT_INVALID_ARG;
   } 

   /* decrypt and xor IV against the plaintext of the previous step */
   cipher_descriptor[cbc->cipher].ecb_decrypt(ct, tmp, &cbc->key);
   for (x = 0; x < cbc->blocklen; x++) { 
       /* copy CT in case ct == pt */
       tmp2[x] = ct[x]; 

       /* actually decrypt the byte */
       pt[x] = tmp[x] ^ cbc->IV[x]; 
   }

   /* replace IV with this current ciphertext */ 
   for (x = 0; x < cbc->blocklen; x++) {
       cbc->IV[x] = tmp2[x];
   }
   #ifdef CLEAN_STACK
      zeromem(tmp, sizeof(tmp));
      zeromem(tmp2, sizeof(tmp2));
   #endif
   return CRYPT_OK;
}

#endif

