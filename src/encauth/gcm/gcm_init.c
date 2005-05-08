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

/**
   @file gcm_init.c
   GCM implementation, initialize state, by Tom St Denis
*/
#include "tomcrypt.h"

#ifdef GCM_MODE

/**
  Initialize a GCM state
  @param gcm     The GCM state to initialize
  @param cipher  The index of the cipher to use
  @param key     The secret key
  @param keylen  The length of the secret key
  @return CRYPT_OK on success
 */
int gcm_init(gcm_state *gcm, int cipher, 
             const unsigned char *key,  int keylen)
{
   int           err;
   unsigned char B[16];
#ifdef GCM_TABLES
   int           x, y;
#endif

   LTC_ARGCHK(gcm != NULL);
   LTC_ARGCHK(key != NULL);

#ifdef LTC_FAST
   if (16 % sizeof(LTC_FAST_TYPE)) {
      return CRYPT_INVALID_ARG;
   }
#endif

   /* is cipher valid? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }
   if (cipher_descriptor[cipher].block_length != 16) {
      return CRYPT_INVALID_CIPHER;
   }

   /* schedule key */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, 0, &gcm->K)) != CRYPT_OK) {
      return err;
   }

   /* H = E(0) */
   zeromem(B, 16);
   cipher_descriptor[cipher].ecb_encrypt(B, gcm->H, &gcm->K);

   /* setup state */
   zeromem(gcm->buf, sizeof(gcm->buf));
   zeromem(gcm->X,   sizeof(gcm->X));
   gcm->cipher   = cipher;
   gcm->mode     = GCM_MODE_IV;
   gcm->ivmode   = 0;
   gcm->buflen   = 0;
   gcm->totlen   = 0;
   gcm->pttotlen = 0;

#ifdef GCM_TABLES
   /* setup tables */
   zeromem(B, 16);
   for (x = 0; x < 16; x++) {
       for (y = 0; y < 256; y++) {
            B[x] = y;
            gcm_gf_mult(gcm->H, B, &gcm->PC[x][y][0]);
       }
       B[x] = 0;
   }
#endif

   return CRYPT_OK;
}

#endif
