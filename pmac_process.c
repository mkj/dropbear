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

int pmac_process(pmac_state *state, const unsigned char *buf, unsigned long len)
{
   int err, n, x;
   unsigned char Z[MAXBLOCKSIZE];

   _ARGCHK(state != NULL);
   _ARGCHK(buf   != NULL);
   if ((err = cipher_is_valid(state->cipher_idx)) != CRYPT_OK) {
      return err;
   }

   if ((state->buflen > (int)sizeof(state->block)) || (state->buflen < 0) ||
       (state->block_len > (int)sizeof(state->block)) || (state->buflen > state->block_len)) {
      return CRYPT_INVALID_ARG;
   }

   while (len != 0) { 
       /* ok if the block is full we xor in prev, encrypt and replace prev */
       if (state->buflen == state->block_len) {
          pmac_shift_xor(state);
          for (x = 0; x < state->block_len; x++) {
              Z[x] = state->Li[x] ^ state->block[x];
          }
          cipher_descriptor[state->cipher_idx].ecb_encrypt(Z, Z, &state->key);
          for (x = 0; x < state->block_len; x++) {
              state->checksum[x] ^= Z[x];
          }
          state->buflen = 0;
       }

       /* add bytes */
       n = MIN(len, (unsigned long)(state->block_len - state->buflen));
       XMEMCPY(state->block + state->buflen, buf, n);
       state->buflen += n;
       len           -= n;
       buf           += n;
   }

#ifdef CLEAN_STACK
   zeromem(Z, sizeof(Z));
#endif

   return CRYPT_OK;
}

#endif
