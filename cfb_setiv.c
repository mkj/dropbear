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

#ifdef CFB

int cfb_setiv(const unsigned char *IV, unsigned long len, symmetric_CFB *cfb)
{
   int err;
   
   _ARGCHK(IV  != NULL);
   _ARGCHK(cfb != NULL);

   if ((err = cipher_is_valid(cfb->cipher)) != CRYPT_OK) {
       return err;
   }
   
   if (len != (unsigned long)cfb->blocklen) {
      return CRYPT_INVALID_ARG;
   }
      
   /* force next block */
   cfb->padlen = 0;
   cipher_descriptor[cfb->cipher].ecb_encrypt(IV, cfb->IV, &cfb->key);

   return CRYPT_OK;
}

#endif 

