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

int ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_ECB *ecb)
{
   int err;
   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);
   _ARGCHK(ecb != NULL);

   /* valid cipher? */
   if ((err = cipher_is_valid(ecb->cipher)) != CRYPT_OK) {
       return err;
   }
   _ARGCHK(cipher_descriptor[ecb->cipher].ecb_decrypt != NULL);
   
   cipher_descriptor[ecb->cipher].ecb_decrypt(ct, pt, &ecb->key);
   return CRYPT_OK;
}

#endif


