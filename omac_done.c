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

int omac_done(omac_state *state, unsigned char *out, unsigned long *outlen)
{
   int       err, mode;
   unsigned  x;

   _ARGCHK(state  != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);
   if ((err = cipher_is_valid(state->cipher_idx)) != CRYPT_OK) {
      return err;
   }

   if ((state->buflen > (int)sizeof(state->block)) || (state->buflen < 0) ||
       (state->blklen > (int)sizeof(state->block)) || (state->buflen > state->blklen)) {
      return CRYPT_INVALID_ARG;
   }

   /* figure out mode */
   if (state->buflen != state->blklen) {
      /* add the 0x80 byte */
      state->block[state->buflen++] = 0x80;

      /* pad with 0x00 */
      while (state->buflen < state->blklen) {
         state->block[state->buflen++] = 0x00;
      }
      mode = 1;
   } else {
      mode = 0;
   }

   /* now xor prev + Lu[mode] */
   for (x = 0; x < (unsigned)state->blklen; x++) {
       state->block[x] ^= state->prev[x] ^ state->Lu[mode][x];
   }

   /* encrypt it */
   cipher_descriptor[state->cipher_idx].ecb_encrypt(state->block, state->block, &state->key);
 
   /* output it */
   for (x = 0; x < (unsigned)state->blklen && x < *outlen; x++) {
       out[x] = state->block[x];
   }
   *outlen = x;

#ifdef CLEAN_STACK
   zeromem(state, sizeof(*state));
#endif
   return CRYPT_OK;
}

#endif

