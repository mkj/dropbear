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

int omac_process(omac_state *state, const unsigned char *buf, unsigned long len)
{
   int err, n, x;

   _ARGCHK(state != NULL);
   _ARGCHK(buf   != NULL);
   if ((err = cipher_is_valid(state->cipher_idx)) != CRYPT_OK) {
      return err;
   }

   if ((state->buflen > (int)sizeof(state->block)) || (state->buflen < 0) ||
       (state->blklen > (int)sizeof(state->block)) || (state->buflen > state->blklen)) {
      return CRYPT_INVALID_ARG;
   }

   while (len != 0) { 
       /* ok if the block is full we xor in prev, encrypt and replace prev */
       if (state->buflen == state->blklen) {
          for (x = 0; x < state->blklen; x++) {
              state->block[x] ^= state->prev[x];
          }
          cipher_descriptor[state->cipher_idx].ecb_encrypt(state->block, state->prev, &state->key);
          state->buflen = 0;
       }

       /* add bytes */
       n = MIN(len, (unsigned long)(state->blklen - state->buflen));
       memcpy(state->block + state->buflen, buf, n);
       state->buflen += n;
       len           -= n;
       buf           += n;
   }

   return CRYPT_OK;
}

#endif

