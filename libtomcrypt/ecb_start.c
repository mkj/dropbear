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

#endif
