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

/* PMAC implementation by Tom St Denis */
#include "mycrypt.h"

#ifdef PMAC

static const struct {
    int           len;
    unsigned char poly_div[MAXBLOCKSIZE], 
                  poly_mul[MAXBLOCKSIZE];
} polys[] = {
{
    8,
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B }
}, {
    16, 
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 }
}
};

int pmac_init(pmac_state *pmac, int cipher, const unsigned char *key, unsigned long keylen)
{
   int poly, x, y, m, err;
   unsigned char L[MAXBLOCKSIZE];

   _ARGCHK(pmac  != NULL);
   _ARGCHK(key   != NULL);

   /* valid cipher? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   /* determine which polys to use */
   pmac->block_len = cipher_descriptor[cipher].block_length;
   for (poly = 0; poly < (int)(sizeof(polys)/sizeof(polys[0])); poly++) {
       if (polys[poly].len == pmac->block_len) { 
          break;
       }
   }
   if (polys[poly].len != pmac->block_len) {
      return CRYPT_INVALID_ARG;
   }   

   /* schedule the key */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, 0, &pmac->key)) != CRYPT_OK) {
      return err;
   }
 
   /* find L = E[0] */
   zeromem(L, pmac->block_len);
   cipher_descriptor[cipher].ecb_encrypt(L, L, &pmac->key);

   /* find Ls[i] = L << i for i == 0..31 */
   memcpy(pmac->Ls[0], L, pmac->block_len);
   for (x = 1; x < 32; x++) {
       m = pmac->Ls[x-1][0] >> 7;
       for (y = 0; y < pmac->block_len-1; y++) {
           pmac->Ls[x][y] = ((pmac->Ls[x-1][y] << 1) | (pmac->Ls[x-1][y+1] >> 7)) & 255;
       }
       pmac->Ls[x][pmac->block_len-1] = (pmac->Ls[x-1][pmac->block_len-1] << 1) & 255;

       if (m == 1) {
          for (y = 0; y < pmac->block_len; y++) {
              pmac->Ls[x][y] ^= polys[poly].poly_mul[y];
          }
       }
    }

    /* find Lr = L / x */
    m = L[pmac->block_len-1] & 1;

    /* shift right */
    for (x = pmac->block_len - 1; x > 0; x--) {
        pmac->Lr[x] = ((L[x] >> 1) | (L[x-1] << 7)) & 255;
    }
    pmac->Lr[0] = L[0] >> 1;

    if (m == 1) {
       for (x = 0; x < pmac->block_len; x++) {
           pmac->Lr[x] ^= polys[poly].poly_div[x];
       }
    }

    /* zero buffer, counters, etc... */
    pmac->block_index = 1;
    pmac->cipher_idx  = cipher;
    pmac->buflen      = 0;
    zeromem(pmac->block,    sizeof(pmac->block));
    zeromem(pmac->Li,       sizeof(pmac->Li));
    zeromem(pmac->checksum, sizeof(pmac->checksum));

#ifdef CLEAN_STACK
    zeromem(L, sizeof(L));
#endif

    return CRYPT_OK;
}

static int ntz(unsigned long x)
{
   int c;
   x &= 0xFFFFFFFFUL;
   c = 0;
   while ((x & 1) == 0) {
      ++c;
      x >>= 1;
   }
   return c;
}

static void shift_xor(pmac_state *pmac)
{
   int x, y;
   y = ntz(pmac->block_index++);
   for (x = 0; x < pmac->block_len; x++) {
       pmac->Li[x] ^= pmac->Ls[y][x];
   }
}

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
          shift_xor(state);
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
       memcpy(state->block + state->buflen, buf, n);
       state->buflen += n;
       len           -= n;
       buf           += n;
   }

#ifdef CLEAN_STACK
   zeromem(Z, sizeof(Z));
#endif

   return CRYPT_OK;
}

int pmac_done(pmac_state *state, unsigned char *out, unsigned long *outlen)
{
   int err, x;

   _ARGCHK(state != NULL);
   _ARGCHK(out   != NULL);
   if ((err = cipher_is_valid(state->cipher_idx)) != CRYPT_OK) {
      return err;
   }

   if ((state->buflen > (int)sizeof(state->block)) || (state->buflen < 0) ||
       (state->block_len > (int)sizeof(state->block)) || (state->buflen > state->block_len)) {
      return CRYPT_INVALID_ARG;
   }


   /* handle padding.  If multiple xor in L/x */

   if (state->buflen == state->block_len) {
      /* xor Lr against the checksum */
      for (x = 0; x < state->block_len; x++) {
          state->checksum[x] ^= state->block[x] ^ state->Lr[x];
      }
   } else {
      /* otherwise xor message bytes then the 0x80 byte */
      for (x = 0; x < state->buflen; x++) {
          state->checksum[x] ^= state->block[x];
      }
      state->checksum[x] ^= 0x80;
   }

   /* encrypt it */
   cipher_descriptor[state->cipher_idx].ecb_encrypt(state->checksum, state->checksum, &state->key);

   /* store it */
   for (x = 0; x < state->block_len && x <= (int)*outlen; x++) {
       out[x] = state->checksum[x];
   }
   *outlen = x;

#ifdef CLEAN_STACK
   zeromem(state, sizeof(*state));
#endif
   return CRYPT_OK;
}

int pmac_memory(int cipher, const unsigned char *key, unsigned long keylen,
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

int pmac_file(int cipher, const unsigned char *key, unsigned long keylen,
              const char *filename, unsigned char *out, unsigned long *outlen)
{
#ifdef NO_FILE
   return CRYPT_NOP;
#else
   int err, x;
   pmac_state pmac;
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

   if ((err = pmac_init(&pmac, cipher, key, keylen)) != CRYPT_OK) {
      fclose(in);
      return err;
   }

   do {
      x = fread(buf, 1, sizeof(buf), in);
      if ((err = pmac_process(&pmac, buf, x)) != CRYPT_OK) {
         fclose(in);
         return err;
      }
   } while (x == sizeof(buf));
   fclose(in);

   if ((err = pmac_done(&pmac, out, outlen)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif

   return CRYPT_OK;
#endif
}

int pmac_test(void)
{
#if !defined(LTC_TEST)
    return CRYPT_NOP;
#else
    static const struct { 
        int msglen;
        unsigned char key[16], msg[34], tag[16];
    } tests[] = {

   /* PMAC-AES-128-0B */
{
   0,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* msg */
   { 0x00 },
   /* tag */
   { 0x43, 0x99, 0x57, 0x2c, 0xd6, 0xea, 0x53, 0x41,
     0xb8, 0xd3, 0x58, 0x76, 0xa7, 0x09, 0x8a, 0xf7 }
},

   /* PMAC-AES-128-3B */
{
   3,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* msg */
   { 0x00, 0x01, 0x02 },
   /* tag */
   { 0x25, 0x6b, 0xa5, 0x19, 0x3c, 0x1b, 0x99, 0x1b,
     0x4d, 0xf0, 0xc5, 0x1f, 0x38, 0x8a, 0x9e, 0x27 }
},

   /* PMAC-AES-128-16B */
{
   16,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* msg */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* tag */
   { 0xeb, 0xbd, 0x82, 0x2f, 0xa4, 0x58, 0xda, 0xf6,
     0xdf, 0xda, 0xd7, 0xc2, 0x7d, 0xa7, 0x63, 0x38 }
},

   /* PMAC-AES-128-20B */
{
   20,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* msg */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13 },
   /* tag */
   { 0x04, 0x12, 0xca, 0x15, 0x0b, 0xbf, 0x79, 0x05,
     0x8d, 0x8c, 0x75, 0xa5, 0x8c, 0x99, 0x3f, 0x55 }
},

   /* PMAC-AES-128-32B */
{
   32,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* msg */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
   /* tag */
   { 0xe9, 0x7a, 0xc0, 0x4e, 0x9e, 0x5e, 0x33, 0x99,
     0xce, 0x53, 0x55, 0xcd, 0x74, 0x07, 0xbc, 0x75 }
},

   /* PMAC-AES-128-34B */
{
   34,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* msg */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
     0x20, 0x21 },
   /* tag */
   { 0x5c, 0xba, 0x7d, 0x5e, 0xb2, 0x4f, 0x7c, 0x86,
     0xcc, 0xc5, 0x46, 0x04, 0xe5, 0x3d, 0x55, 0x12 }
}

};
   int err, x, idx;
   unsigned long len;
   unsigned char outtag[MAXBLOCKSIZE];

    /* AES can be under rijndael or aes... try to find it */ 
    if ((idx = find_cipher("aes")) == -1) {
       if ((idx = find_cipher("rijndael")) == -1) {
          return CRYPT_NOP;
       }
    }

    for (x = 0; x < (int)(sizeof(tests)/sizeof(tests[0])); x++) {
        len = sizeof(outtag);
        if ((err = pmac_memory(idx, tests[x].key, 16, tests[x].msg, tests[x].msglen, outtag, &len)) != CRYPT_OK) {
           return err;
        }
        
        if (memcmp(outtag, tests[x].tag, len)) {
#if 0
           unsigned long y;
           printf("\nTAG:\n");
           for (y = 0; y < len; ) {
               printf("0x%02x", outtag[y]);
               if (y < len-1) printf(", ");
               if (!(++y % 8)) printf("\n");
           }
#endif
           return CRYPT_FAIL_TESTVECTOR;
        }
     }
     return CRYPT_OK;
#endif /* LTC_TEST */
}

#endif /* PMAC_MODE */


 
