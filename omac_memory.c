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
/* OMAC1 Support by Tom St Denis (for 64 and 128 bit block ciphers only) */
#include "mycrypt.h"

#ifdef OMAC

int omac_memory(int cipher, 
                const unsigned char *key, unsigned long keylen,
                const unsigned char *msg, unsigned long msglen,
                      unsigned char *out, unsigned long *outlen)
{
   int err;
   omac_state *omac;

   _ARGCHK(key    != NULL);
   _ARGCHK(msg    != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

   /* allocate ram for omac state */
   omac = XMALLOC(sizeof(omac_state));
   if (omac == NULL) {
      return CRYPT_MEM;
   }

   /* omac process the message */
   if ((err = omac_init(omac, cipher, key, keylen)) != CRYPT_OK) {
      goto __ERR;
   }
   if ((err = omac_process(omac, msg, msglen)) != CRYPT_OK) {
      goto __ERR;
   }
   if ((err = omac_done(omac, out, outlen)) != CRYPT_OK) {
      goto __ERR;
   }

   err = CRYPT_OK;
__ERR:
#ifdef CLEAN_STACK
   zeromem(omac, sizeof(omac_state));
#endif

   XFREE(omac);
   return err;   
}

#endif
