/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * gurantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://libtomcrypt.org
 */
/* OMAC1 Support by Tom St Denis (for 64 and 128 bit block ciphers only) */
#include "mycrypt.h"

#ifdef OMAC

int omac_init(omac_state *omac, int cipher, const unsigned char *key, unsigned long keylen)
{
   int err, x, y, mask, msb, len;

   _ARGCHK(omac != NULL);
   _ARGCHK(key  != NULL);

   /* schedule the key */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   /* now setup the system */
   switch (cipher_descriptor[cipher].block_length) {
       case 8:  mask = 0x1B;
                len  = 8;
                break;
       case 16: mask = 0x87;
                len  = 16;
                break;
       default: return CRYPT_INVALID_ARG;
   }

   if ((err = cipher_descriptor[cipher].setup(key, keylen, 0, &omac->key)) != CRYPT_OK) {
      return err;
   }

   /* ok now we need Lu and Lu^2 [calc one from the other] */

   /* first calc L which is Ek(0) */
   zeromem(omac->Lu[0], cipher_descriptor[cipher].block_length);
   cipher_descriptor[cipher].ecb_encrypt(omac->Lu[0], omac->Lu[0], &omac->key);

   /* now do the mults, whoopy! */
   for (x = 0; x < 2; x++) {
       /* if msb(L * u^(x+1)) = 0 then just shift, otherwise shift and xor constant mask */
       msb = omac->Lu[x][0] >> 7;

       /* shift left */
       for (y = 0; y < (len - 1); y++) {
           omac->Lu[x][y] = ((omac->Lu[x][y] << 1) | (omac->Lu[x][y+1] >> 7)) & 255;
       }
       omac->Lu[x][len - 1] = ((omac->Lu[x][len - 1] << 1) ^ (msb ? mask : 0)) & 255;
 
       /* copy up as require */
       if (x == 0) {
          memcpy(omac->Lu[1], omac->Lu[0], sizeof(omac->Lu[0]));
       }
   }

   /* setup state */
   omac->cipher_idx = cipher;
   omac->buflen     = 0;
   omac->blklen     = len;
   zeromem(omac->prev,  sizeof(omac->prev));
   zeromem(omac->block, sizeof(omac->block));

   return CRYPT_OK;
}

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

int omac_done(omac_state *state, unsigned char *out, unsigned long *outlen)
{
   int err, mode, x;

   _ARGCHK(state != NULL);
   _ARGCHK(out   != NULL);
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
   for (x = 0; x < state->blklen; x++) {
       state->block[x] ^= state->prev[x] ^ state->Lu[mode][x];
   }

   /* encrypt it */
   cipher_descriptor[state->cipher_idx].ecb_encrypt(state->block, state->block, &state->key);
 
   /* output it */
   for (x = 0; x < state->blklen && (unsigned long)x < *outlen; x++) {
       out[x] = state->block[x];
   }
   *outlen = x;

#ifdef CLEAN_STACK
   zeromem(state, sizeof(*state));
#endif
   return CRYPT_OK;
}

int omac_memory(int cipher, const unsigned char *key, unsigned long keylen,
                const unsigned char *msg, unsigned long msglen,
                unsigned char *out, unsigned long *outlen)
{
   int err;
   omac_state omac;

   _ARGCHK(key != NULL);
   _ARGCHK(msg != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   if ((err = omac_init(&omac, cipher, key, keylen)) != CRYPT_OK) {
      return err;
   }
   if ((err = omac_process(&omac, msg, msglen)) != CRYPT_OK) {
      return err;
   }
   if ((err = omac_done(&omac, out, outlen)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK
   zeromem(&omac, sizeof(omac));
#endif

   return CRYPT_OK;
}

int omac_file(int cipher, const unsigned char *key, unsigned long keylen,
              const char *filename, unsigned char *out, unsigned long *outlen)
{
#ifdef NO_FILE
   return CRYPT_NOP;
#else
   int err, x;
   omac_state omac;
   FILE *in;
   unsigned char buf[512];


   _ARGCHK(key      != NULL);
   _ARGCHK(filename != NULL);
   _ARGCHK(out      != NULL);
   _ARGCHK(outlen   != NULL);


   in = fopen(filename, "rb");
   if (in == NULL) {
      return CRYPT_FILE_NOTFOUND;
   }

   if ((err = omac_init(&omac, cipher, key, keylen)) != CRYPT_OK) {
      fclose(in);
      return err;
   }

   do {
      x = fread(buf, 1, sizeof(buf), in);
      if ((err = omac_process(&omac, buf, x)) != CRYPT_OK) {
         fclose(in);
         return err;
      }
   } while (x == sizeof(buf));
   fclose(in);

   if ((err = omac_done(&omac, out, outlen)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif

   return CRYPT_OK;
#endif
}

int omac_test(void)
{
#if !defined(LTC_TEST)
    return CRYPT_NOP;
#else
    static const struct { 
        int keylen, msglen;
        unsigned char key[16], msg[64], tag[16];
    } tests[] = {
    { 16, 0,
      { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
      { 0x00 },
      { 0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
        0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46 }
    },
    { 16, 16, 
      { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
      { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a },
      { 0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c }
    },
    { 16, 40, 
      { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
      { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11 },
      { 0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
        0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27 }
    },
    { 16, 64, 
      { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
      { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 },
      { 0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe }
    }

    };
    unsigned char out[16];
    int x, y, err, idx;
    unsigned long len;


    /* AES can be under rijndael or aes... try to find it */ 
    if ((idx = find_cipher("aes")) == -1) {
       if ((idx = find_cipher("rijndael")) == -1) {
          return CRYPT_NOP;
       }
    }

    for (x = 0; x < (int)(sizeof(tests)/sizeof(tests[0])); x++) {
       len = sizeof(out); 
       if ((err = omac_memory(idx, tests[x].key, tests[x].keylen, tests[x].msg, tests[x].msglen, out, &len)) != CRYPT_OK) {
          return err;
       }

       if (memcmp(out, tests[x].tag, 16) != 0) {
          printf("\n\nTag: ");
          for (y = 0; y < 16; y++) printf("%02x", out[y]); printf("\n\n");
          return CRYPT_FAIL_TESTVECTOR;
       }
    }
    return CRYPT_OK;
#endif
}   

#endif
