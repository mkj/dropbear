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

int eax_init(eax_state *eax, int cipher, const unsigned char *key, unsigned long keylen,
             const unsigned char *nonce, unsigned long noncelen,
             const unsigned char *header, unsigned long headerlen)
{
   unsigned char *buf;
   int           err, blklen;
   omac_state    *omac;
   unsigned long len;


   _ARGCHK(eax   != NULL);
   _ARGCHK(key   != NULL);
   _ARGCHK(nonce != NULL);
   if (headerlen > 0) {
      _ARGCHK(header != NULL);
   }

   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   blklen = cipher_descriptor[cipher].block_length;

   /* allocate ram */
   buf  = XMALLOC(MAXBLOCKSIZE);
   omac = XMALLOC(sizeof(omac_state));

   if (buf == NULL || omac == NULL) {
      if (buf != NULL) {
         XFREE(buf);
      }
      if (omac != NULL) {
         XFREE(omac);
      }
      return CRYPT_MEM;
   }

   /* N = OMAC_0K(nonce) */
   zeromem(buf, MAXBLOCKSIZE);
   if ((err = omac_init(omac, cipher, key, keylen)) != CRYPT_OK) {
      goto __ERR; 
   }

   /* omac the [0]_n */
   if ((err = omac_process(omac, buf, blklen)) != CRYPT_OK) {
      goto __ERR; 
   }
   /* omac the nonce */
   if ((err = omac_process(omac, nonce, noncelen)) != CRYPT_OK) {
      goto __ERR; 
   }
   /* store result */
   len = sizeof(eax->N);
   if ((err = omac_done(omac, eax->N, &len)) != CRYPT_OK) {
      goto __ERR; 
   }

   /* H = OMAC_1K(header) */
   zeromem(buf, MAXBLOCKSIZE);
   buf[blklen - 1] = 1;

   if ((err = omac_init(&eax->headeromac, cipher, key, keylen)) != CRYPT_OK) {
      goto __ERR; 
   }

   /* omac the [1]_n */
   if ((err = omac_process(&eax->headeromac, buf, blklen)) != CRYPT_OK) {
      goto __ERR; 
   }
   /* omac the header */
   if (headerlen != 0) {
      if ((err = omac_process(&eax->headeromac, header, headerlen)) != CRYPT_OK) {
          goto __ERR; 
      }
   }

   /* note we don't finish the headeromac, this allows us to add more header later */

   /* setup the CTR mode */
   if ((err = ctr_start(cipher, eax->N, key, keylen, 0, &eax->ctr)) != CRYPT_OK) {
      goto __ERR; 
   }
   /* use big-endian counter */
   eax->ctr.mode = 1;

   /* setup the OMAC for the ciphertext */
   if ((err = omac_init(&eax->ctomac, cipher, key, keylen)) != CRYPT_OK) { 
      goto __ERR; 
   }

   /* omac [2]_n */
   zeromem(buf, MAXBLOCKSIZE);
   buf[blklen-1] = 2;
   if ((err = omac_process(&eax->ctomac, buf, blklen)) != CRYPT_OK) {
      goto __ERR; 
   }

   err = CRYPT_OK;
__ERR:
#ifdef CLEAN_STACK
   zeromem(buf,  MAXBLOCKSIZE);
   zeromem(omac, sizeof(omac_state));
#endif

   XFREE(omac);
   XFREE(buf);

   return err;
}

#endif 
