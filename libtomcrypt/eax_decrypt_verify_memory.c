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

int eax_decrypt_verify_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  unsigned long noncelen,
    const unsigned char *header, unsigned long headerlen,
    const unsigned char *ct,     unsigned long ctlen,
          unsigned char *pt,
          unsigned char *tag,    unsigned long taglen,
          int           *res)
{
   int err;
   eax_state eax;
   unsigned char buf[MAXBLOCKSIZE];
   unsigned long buflen;

   _ARGCHK(res != NULL);

   /* default to zero */
   *res = 0;

   if ((err = eax_init(&eax, cipher, key, keylen, nonce, noncelen, header, headerlen)) != CRYPT_OK) {
      return err;
   }

   if ((err = eax_decrypt(&eax, ct, pt, ctlen)) != CRYPT_OK) {
      return err;
   }
 
   buflen = MIN(sizeof(buf), taglen);
   if ((err = eax_done(&eax, buf, &buflen)) != CRYPT_OK) {
      return err;
   }

   /* compare tags */
   if (buflen >= taglen && memcmp(buf, tag, taglen) == 0) {
      *res = 1;
   }

#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return CRYPT_OK;
}

#endif
