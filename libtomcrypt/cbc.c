#include "mycrypt.h"

#ifdef CBC

int cbc_start(int cipher, const unsigned char *IV, const unsigned char *key, 
              int keylen, int num_rounds, symmetric_CBC *cbc)
{
   int x, err;
 
   _ARGCHK(IV != NULL);
   _ARGCHK(key != NULL);
   _ARGCHK(cbc != NULL);

   /* bad param? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   /* setup cipher */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, num_rounds, &cbc->key)) != CRYPT_OK) {
      return err;
   }

   /* copy IV */
   cbc->blocklen = cipher_descriptor[cipher].block_length;
   cbc->cipher   = cipher;
   for (x = 0; x < cbc->blocklen; x++) {
       cbc->IV[x] = IV[x];
   }
   return CRYPT_OK;
}

int cbc_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_CBC *cbc)
{
   int x, err;
   unsigned char tmp[MAXBLOCKSIZE];

   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);
   _ARGCHK(cbc != NULL);

   if ((err = cipher_is_valid(cbc->cipher)) != CRYPT_OK) {
       return err;
   }
   
   /* is blocklen valid? */
   if (cbc->blocklen < 0 || cbc->blocklen > (int)sizeof(cbc->IV)) {
      return CRYPT_INVALID_ARG;
   }    

   /* xor IV against plaintext */
   for (x = 0; x < cbc->blocklen; x++) {
       tmp[x] = pt[x] ^ cbc->IV[x];
   }

   /* encrypt */
   cipher_descriptor[cbc->cipher].ecb_encrypt(tmp, ct, &cbc->key);

   /* store IV [ciphertext] for a future block */
   for (x = 0; x < cbc->blocklen; x++) {
       cbc->IV[x] = ct[x];
   }

   #ifdef CLEAN_STACK
      zeromem(tmp, sizeof(tmp));
   #endif
   return CRYPT_OK;
}

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
   cipher_descriptor[cbc->cipher].ecb_decrypt(ct, tmp, &cbc->key);
   
   /* is blocklen valid? */
   if (cbc->blocklen < 0 || cbc->blocklen > (int)sizeof(cbc->IV)) {
      return CRYPT_INVALID_ARG;
   } 

   /* xor IV against the plaintext of the previous step */
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

