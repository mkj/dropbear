#include "mycrypt.h"

#ifdef ECB

int ecb_start(int cipher, const unsigned char *key, int keylen, int num_rounds, symmetric_ECB *ecb)
{
   int err;
   _ARGCHK(key != NULL);
   _ARGCHK(ecb != NULL);

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   ecb->cipher = cipher;
   ecb->blocklen = cipher_descriptor[cipher].block_length;
   return cipher_descriptor[cipher].setup(key, keylen, num_rounds, &ecb->key);
}

int ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_ECB *ecb)
{
   int err;
   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);
   _ARGCHK(ecb != NULL);

   if ((err = cipher_is_valid(ecb->cipher)) != CRYPT_OK) {
       return err;
   }
   cipher_descriptor[ecb->cipher].ecb_encrypt(pt, ct, &ecb->key);
   return CRYPT_OK;
}

int ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_ECB *ecb)
{
   int err;
   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);
   _ARGCHK(ecb != NULL);

   if ((err = cipher_is_valid(ecb->cipher)) != CRYPT_OK) {
       return err;
   }
   cipher_descriptor[ecb->cipher].ecb_decrypt(ct, pt, &ecb->key);
   return CRYPT_OK;
}

#endif


