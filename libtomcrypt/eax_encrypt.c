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

int eax_encrypt(eax_state *eax, const unsigned char *pt, unsigned char *ct, unsigned long length)
{
   int err;
   
   _ARGCHK(eax != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);

   /* encrypt */
   if ((err = ctr_encrypt(pt, ct, length, &eax->ctr)) != CRYPT_OK) {
      return err;
   }

   /* omac ciphertext */
   return omac_process(&eax->ctomac, ct, length);
}

#endif

