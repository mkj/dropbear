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
   int            err;
   eax_state     *eax;
   unsigned char *buf;
   unsigned long  buflen;

   _ARGCHK(res != NULL);

   /* default to zero */
   *res = 0;

   /* allocate ram */
   buf = XMALLOC(taglen);
   eax = XMALLOC(sizeof(eax_state));
   if (eax == NULL || buf == NULL) {
      if (eax != NULL) {
         XFREE(eax);
      }
      if (buf != NULL) {
         XFREE(buf);
      }
      return CRYPT_MEM;
   }

   if ((err = eax_init(eax, cipher, key, keylen, nonce, noncelen, header, headerlen)) != CRYPT_OK) {
      goto __ERR;
   }

   if ((err = eax_decrypt(eax, ct, pt, ctlen)) != CRYPT_OK) {
      goto __ERR;
   }
 
   buflen = taglen;
   if ((err = eax_done(eax, buf, &buflen)) != CRYPT_OK) {
      goto __ERR;
   }

   /* compare tags */
   if (buflen >= taglen && memcmp(buf, tag, taglen) == 0) {
      *res = 1;
   }
   
   err = CRYPT_OK;
__ERR:
#ifdef CLEAN_STACK
   zeromem(buf, taglen);
   zeromem(eax, sizeof(eax_state));
#endif

   XFREE(eax);
   XFREE(buf);

   return err;
}

#endif
