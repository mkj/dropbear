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

/* PMAC implementation by Tom St Denis */
#include "mycrypt.h"

#ifdef PMAC

int pmac_memory(int cipher, 
                const unsigned char *key, unsigned long keylen,
                const unsigned char *msg, unsigned long msglen,
                      unsigned char *out, unsigned long *outlen)
{
   int err;
   pmac_state pmac;

   _ARGCHK(key    != NULL);
   _ARGCHK(msg    != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);


   if ((err = pmac_init(&pmac, cipher, key, keylen)) != CRYPT_OK) {
      return err;
   }
   if ((err = pmac_process(&pmac, msg, msglen)) != CRYPT_OK) {
      return err;
   }
   if ((err = pmac_done(&pmac, out, outlen)) != CRYPT_OK) {
      return err;
   }

   return CRYPT_OK;
}

#endif
