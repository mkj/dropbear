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

/* EAX Implementation by Tom St Denis */
#include "mycrypt.h"

#ifdef EAX_MODE

int eax_decrypt(eax_state *eax, const unsigned char *ct, unsigned char *pt, unsigned long length)
{
   int err;
   
   _ARGCHK(eax != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);

   /* omac ciphertext */
   if ((err = omac_process(&eax->ctomac, ct, length)) != CRYPT_OK) {
      return err;
   }

   /* decrypt  */
   return ctr_decrypt(ct, pt, length, &eax->ctr);
}

#endif
