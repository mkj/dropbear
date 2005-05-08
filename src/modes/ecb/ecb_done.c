/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */
#include "tomcrypt.h"

/**
   @file ecb_done.c
   ECB implementation, finish chain, Tom St Denis
*/

#ifdef ECB

/** Terminate the chain
  @param rcb    The ECB chain to terminate
  @return CRYPT_OK on success
*/
int ecb_done(symmetric_ECB *ecb)
{
   int err;
   LTC_ARGCHK(ecb != NULL);

   if ((err = cipher_is_valid(ecb->cipher)) != CRYPT_OK) {
      return err;
   }
   cipher_descriptor[ecb->cipher].done(&ecb->key);
   return CRYPT_OK;
}

   

#endif
