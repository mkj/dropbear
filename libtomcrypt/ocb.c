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

/* OCB Implementation by Tom St Denis */
#include "mycrypt.h"

#define OCB_MODE
#ifdef OCB_MODE

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

int ocb_init(ocb_state *ocb, int cipher, 
             const unsigned char *key, unsigned long keylen, const unsigned char *nonce)
{
   int poly, x, y, m, err;

   _ARGCHK(ocb   != NULL);
   _ARGCHK(key   != NULL);
   _ARGCHK(nonce != NULL);

   /* valid cipher? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   /* determine which polys to use */
   ocb->block_len = cipher_descriptor[cipher].block_length;
   for (poly = 0; poly < (int)(sizeof(polys)/sizeof(polys[0])); poly++) {
       if (polys[poly].len == ocb->block_len) { 
          break;
       }
   }
   if (polys[poly].len != ocb->block_len) {
      return CRYPT_INVALID_ARG;
   }   

   /* schedule the key */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, 0, &ocb->key)) != CRYPT_OK) {
      return err;
   }
 
   /* find L = E[0] */
   zeromem(ocb->L, ocb->block_len);
   cipher_descriptor[cipher].ecb_encrypt(ocb->L, ocb->L, &ocb->key);

   /* find R = E[N xor L] */
   for (x = 0; x < ocb->block_len; x++) {
       ocb->R[x] = ocb->L[x] ^ nonce[x];
   }
   cipher_descriptor[cipher].ecb_encrypt(ocb->R, ocb->R, &ocb->key);

   /* find Ls[i] = L << i for i == 0..31 */
   memcpy(ocb->Ls[0], ocb->L, ocb->block_len);
   for (x = 1; x < 32; x++) {
       m = ocb->Ls[x-1][0] >> 7;
       for (y = 0; y < ocb->block_len-1; y++) {
           ocb->Ls[x][y] = ((ocb->Ls[x-1][y] << 1) | (ocb->Ls[x-1][y+1] >> 7)) & 255;
       }
       ocb->Ls[x][ocb->block_len-1] = (ocb->Ls[x-1][ocb->block_len-1] << 1) & 255;

       if (m == 1) {
          for (y = 0; y < ocb->block_len; y++) {
              ocb->Ls[x][y] ^= polys[poly].poly_mul[y];
          }
       }
    }

    /* find Lr = L / x */
    m = ocb->L[ocb->block_len-1] & 1;

    /* shift right */
    for (x = ocb->block_len - 1; x > 0; x--) {
        ocb->Lr[x] = ((ocb->L[x] >> 1) | (ocb->L[x-1] << 7)) & 255;
    }
    ocb->Lr[0] = ocb->L[0] >> 1;

    if (m == 1) {
       for (x = 0; x < ocb->block_len; x++) {
           ocb->Lr[x] ^= polys[poly].poly_div[x];
       }
    }

    /* set Li, checksum */
    zeromem(ocb->Li, ocb->block_len);
    zeromem(ocb->checksum, ocb->block_len);

    /* set other params */
    ocb->block_index = 1;
    ocb->cipher      = cipher;

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

static void shift_xor(ocb_state *ocb, unsigned char *Z)
{
   int x, y;
   y = ntz(ocb->block_index++);
   for (x = 0; x < ocb->block_len; x++) {
       ocb->Li[x] ^= ocb->Ls[y][x];
       Z[x]        = ocb->Li[x] ^ ocb->R[x];
   }
}

int ocb_encrypt(ocb_state *ocb, const unsigned char *pt, unsigned char *ct)
{
   unsigned char Z[MAXBLOCKSIZE], tmp[MAXBLOCKSIZE];
   int err, x;

   _ARGCHK(ocb != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);
   if ((err = cipher_is_valid(ocb->cipher)) != CRYPT_OK) {
      return err;
   }
   if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length) {
      return CRYPT_INVALID_ARG;
   }

   /* compute checksum */
   for (x = 0; x < ocb->block_len; x++) {
       ocb->checksum[x] ^= pt[x];
   }

   /* Get Z[i] value */
   shift_xor(ocb, Z);

   /* xor pt in, encrypt, xor Z out */
   for (x = 0; x < ocb->block_len; x++) {
       tmp[x] = pt[x] ^ Z[x];
   }
   cipher_descriptor[ocb->cipher].ecb_encrypt(tmp, ct, &ocb->key);
   for (x = 0; x < ocb->block_len; x++) {
       ct[x] ^= Z[x];
   }

#ifdef CLEAN_STACK
   zeromem(Z, sizeof(Z));
   zeromem(tmp, sizeof(tmp));
#endif
   return CRYPT_OK;
}

int ocb_decrypt(ocb_state *ocb, const unsigned char *ct, unsigned char *pt)
{
   unsigned char Z[MAXBLOCKSIZE], tmp[MAXBLOCKSIZE];
   int err, x;

   _ARGCHK(ocb != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);
   if ((err = cipher_is_valid(ocb->cipher)) != CRYPT_OK) {
      return err;
   }
   if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length) {
      return CRYPT_INVALID_ARG;
   }

   /* Get Z[i] value */
   shift_xor(ocb, Z);

   /* xor ct in, encrypt, xor Z out */
   for (x = 0; x < ocb->block_len; x++) {
       tmp[x] = ct[x] ^ Z[x];
   }
   cipher_descriptor[ocb->cipher].ecb_decrypt(tmp, pt, &ocb->key);
   for (x = 0; x < ocb->block_len; x++) {
       pt[x] ^= Z[x];
   }

   /* compute checksum */
   for (x = 0; x < ocb->block_len; x++) {
       ocb->checksum[x] ^= pt[x];
   }


#ifdef CLEAN_STACK
   zeromem(Z, sizeof(Z));
   zeromem(tmp, sizeof(tmp));
#endif
   return CRYPT_OK;
}


/* Since the last block is encrypted in CTR mode the same code can
 * be used to finish a decrypt or encrypt stream.  The only difference
 * is we XOR the final ciphertext into the checksum so we have to xor it
 * before we CTR [decrypt] or after [encrypt]
 *
 * the names pt/ptlen/ct really just mean in/inlen/out but this is the way I wrote it... 
 */
static int _ocb_done(ocb_state *ocb, const unsigned char *pt, unsigned long ptlen,
                     unsigned char *ct, unsigned char *tag, unsigned long *taglen, int mode)

{
   unsigned char Z[MAXBLOCKSIZE], Y[MAXBLOCKSIZE], X[MAXBLOCKSIZE];
   int err, x;

   _ARGCHK(ocb    != NULL);
   _ARGCHK(pt     != NULL);
   _ARGCHK(ct     != NULL);
   _ARGCHK(tag    != NULL);
   _ARGCHK(taglen != NULL);
   if ((err = cipher_is_valid(ocb->cipher)) != CRYPT_OK) {
      return err;
   }
   if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length ||
       (int)ptlen > ocb->block_len || (int)ptlen < 0) {
      return CRYPT_INVALID_ARG;
   }

   /* compute X[m] = len(pt[m]) XOR Lr XOR Z[m] */
   shift_xor(ocb, X); 
   memcpy(Z, X, ocb->block_len);

   X[ocb->block_len-1] ^= (ptlen*8)&255;
   X[ocb->block_len-2] ^= ((ptlen*8)>>8)&255;
   for (x = 0; x < ocb->block_len; x++) {
       X[x] ^= ocb->Lr[x]; 
   }

   /* Y[m] = E(X[m])) */
   cipher_descriptor[ocb->cipher].ecb_encrypt(X, Y, &ocb->key);

   if (mode == 1) {
      /* decrypt mode, so let's xor it first */
      /* xor C[m] into checksum */
      for (x = 0; x < (int)ptlen; x++) {
         ocb->checksum[x] ^= ct[x];
      }  
   }

   /* C[m] = P[m] xor Y[m] */
   for (x = 0; x < (int)ptlen; x++) {
       ct[x] = pt[x] ^ Y[x];
   }

   if (mode == 0) {
      /* encrypt mode */    
      /* xor C[m] into checksum */
      for (x = 0; x < (int)ptlen; x++) {
          ocb->checksum[x] ^= ct[x];
      }
   }

   /* xor Y[m] and Z[m] into checksum */
   for (x = 0; x < ocb->block_len; x++) {
       ocb->checksum[x] ^= Y[x] ^ Z[x];
   }
   
   /* encrypt checksum, er... tag!! */
   cipher_descriptor[ocb->cipher].ecb_encrypt(ocb->checksum, X, &ocb->key);

   /* now store it */
   for (x = 0; x < ocb->block_len && x < (int)*taglen; x++) {
       tag[x] = X[x];
   }
   *taglen = x;

#ifdef CLEAN_STACK
   zeromem(X, sizeof(X));
   zeromem(Y, sizeof(Y));
   zeromem(Z, sizeof(Z));
   zeromem(ocb, sizeof(*ocb));
#endif
   return CRYPT_OK;
}

int ocb_done_encrypt(ocb_state *ocb, const unsigned char *pt, unsigned long ptlen,
                     unsigned char *ct, unsigned char *tag, unsigned long *taglen)
{
   _ARGCHK(ocb    != NULL);
   _ARGCHK(pt     != NULL);
   _ARGCHK(ct     != NULL);
   _ARGCHK(tag    != NULL);
   _ARGCHK(taglen != NULL);
   return _ocb_done(ocb, pt, ptlen, ct, tag, taglen, 0);
}


int ocb_done_decrypt(ocb_state *ocb, 
                     const unsigned char *ct,  unsigned long ctlen,
                           unsigned char *pt, 
                     const unsigned char *tag, unsigned long taglen, int *res)
{
   int err;
   unsigned char tagbuf[MAXBLOCKSIZE];
   unsigned long tagbuflen;

   _ARGCHK(ocb != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);
   _ARGCHK(tag != NULL);
   _ARGCHK(res != NULL);

   *res = 0;

   tagbuflen = sizeof(tagbuf);
   if ((err = _ocb_done(ocb, ct, ctlen, pt, tagbuf, &tagbuflen, 1)) != CRYPT_OK) {
      return err;
   }

   if (taglen <= tagbuflen && memcmp(tagbuf, tag, taglen) == 0) {
      *res = 1;
   }

#ifdef CLEAN_STACK
   zeromem(tagbuf, sizeof(tagbuf));
#endif

   return CRYPT_OK;
}

int ocb_encrypt_authenticate_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  
    const unsigned char *pt,     unsigned long ptlen,
          unsigned char *ct,
          unsigned char *tag,    unsigned long *taglen)
{
   int err;
   ocb_state ocb;

   _ARGCHK(key    != NULL);
   _ARGCHK(nonce  != NULL);
   _ARGCHK(pt     != NULL);
   _ARGCHK(ct     != NULL);
   _ARGCHK(tag    != NULL);
   _ARGCHK(taglen != NULL);

   if ((err = ocb_init(&ocb, cipher, key, keylen, nonce)) != CRYPT_OK) {
      return err;
   }

   while (ptlen > (unsigned long)ocb.block_len) {
        if ((err = ocb_encrypt(&ocb, pt, ct)) != CRYPT_OK) {
           return err;
        }
        ptlen   -= ocb.block_len;
        pt      += ocb.block_len;
        ct      += ocb.block_len;
   }

   err = ocb_done_encrypt(&ocb, pt, ptlen, ct, tag, taglen);

#ifdef CLEAN_STACK
   zeromem(&ocb, sizeof(ocb));
#endif
   return err;
}

int ocb_decrypt_verify_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  
    const unsigned char *ct,     unsigned long ctlen,
          unsigned char *pt,
    const unsigned char *tag,    unsigned long taglen,
          int           *res)
{
   int err;
   ocb_state ocb;


   _ARGCHK(key    != NULL);
   _ARGCHK(nonce  != NULL);
   _ARGCHK(pt     != NULL);
   _ARGCHK(ct     != NULL);
   _ARGCHK(tag    != NULL);
   _ARGCHK(res    != NULL);

   if ((err = ocb_init(&ocb, cipher, key, keylen, nonce)) != CRYPT_OK) {
      return err;
   }

   while (ctlen > (unsigned long)ocb.block_len) {
        if ((err = ocb_decrypt(&ocb, ct, pt)) != CRYPT_OK) {
           return err;
        }
        ctlen   -= ocb.block_len;
        pt      += ocb.block_len;
        ct      += ocb.block_len;
   }

   err = ocb_done_decrypt(&ocb, ct, ctlen, pt, tag, taglen, res);

#ifdef CLEAN_STACK
   zeromem(&ocb, sizeof(ocb));
#endif
   return err;
}

int ocb_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
         int ptlen;
         unsigned char key[16], nonce[16], pt[34], ct[34], tag[16];
   } tests[] = {

   /* OCB-AES-128-0B */
{
   0,
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
   /* pt */
   { 0 },
   /* ct */
   { 0 },
   /* tag */
   { 0x15, 0xd3, 0x7d, 0xd7, 0xc8, 0x90, 0xd5, 0xd6,
     0xac, 0xab, 0x92, 0x7b, 0xc0, 0xdc, 0x60, 0xee },
},


   /* OCB-AES-128-3B */
{
   3, 
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
   /* pt */
   { 0x00, 0x01, 0x02 },
   /* ct */
   { 0xfc, 0xd3, 0x7d },
   /* tag */
   { 0x02, 0x25, 0x47, 0x39, 0xa5, 0xe3, 0x56, 0x5a,
     0xe2, 0xdc, 0xd6, 0x2c, 0x65, 0x97, 0x46, 0xba },
},

   /* OCB-AES-128-16B */
{
   16, 
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
   /* pt */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* ct */
   { 0x37, 0xdf, 0x8c, 0xe1, 0x5b, 0x48, 0x9b, 0xf3,
     0x1d, 0x0f, 0xc4, 0x4d, 0xa1, 0xfa, 0xf6, 0xd6 },
   /* tag */
   { 0xdf, 0xb7, 0x63, 0xeb, 0xdb, 0x5f, 0x0e, 0x71,
     0x9c, 0x7b, 0x41, 0x61, 0x80, 0x80, 0x04, 0xdf },
},

   /* OCB-AES-128-20B  */
{
   20, 
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
   /* pt */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
     0x10, 0x11, 0x12, 0x13 },
   /* ct */
   { 0x01, 0xa0, 0x75, 0xf0, 0xd8, 0x15, 0xb1, 0xa4,
     0xe9, 0xc8, 0x81, 0xa1, 0xbc, 0xff, 0xc3, 0xeb,
     0x70, 0x03, 0xeb, 0x55},
   /* tag */
   { 0x75, 0x30, 0x84, 0x14, 0x4e, 0xb6, 0x3b, 0x77,
     0x0b, 0x06, 0x3c, 0x2e, 0x23, 0xcd, 0xa0, 0xbb },
},

   /* OCB-AES-128-32B  */
{
   32, 
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
   /* pt */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
   /* ct */
   { 0x01, 0xa0, 0x75, 0xf0, 0xd8, 0x15, 0xb1, 0xa4,
     0xe9, 0xc8, 0x81, 0xa1, 0xbc, 0xff, 0xc3, 0xeb,
     0x4a, 0xfc, 0xbb, 0x7f, 0xed, 0xc0, 0x8c, 0xa8,
     0x65, 0x4c, 0x6d, 0x30, 0x4d, 0x16, 0x12, 0xfa },

   /* tag */
   { 0xc1, 0x4c, 0xbf, 0x2c, 0x1a, 0x1f, 0x1c, 0x3c,
     0x13, 0x7e, 0xad, 0xea, 0x1f, 0x2f, 0x2f, 0xcf },
},

   /* OCB-AES-128-34B  */
{
   34, 
   /* key */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
   /* nonce */
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
   /* pt */
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
     0x20, 0x21 },
   /* ct */
   { 0x01, 0xa0, 0x75, 0xf0, 0xd8, 0x15, 0xb1, 0xa4,
     0xe9, 0xc8, 0x81, 0xa1, 0xbc, 0xff, 0xc3, 0xeb,
     0xd4, 0x90, 0x3d, 0xd0, 0x02, 0x5b, 0xa4, 0xaa,
     0x83, 0x7c, 0x74, 0xf1, 0x21, 0xb0, 0x26, 0x0f,
     0xa9, 0x5d },

   /* tag */
   { 0xcf, 0x83, 0x41, 0xbb, 0x10, 0x82, 0x0c, 0xcf,
     0x14, 0xbd, 0xec, 0x56, 0xb8, 0xd7, 0xd6, 0xab },
},

};

   int err, x, idx, res;
   unsigned long len;
   unsigned char outct[MAXBLOCKSIZE], outtag[MAXBLOCKSIZE];

    /* AES can be under rijndael or aes... try to find it */ 
    if ((idx = find_cipher("aes")) == -1) {
       if ((idx = find_cipher("rijndael")) == -1) {
          return CRYPT_NOP;
       }
    }

    for (x = 0; x < (int)(sizeof(tests)/sizeof(tests[0])); x++) {
        len = sizeof(outtag);
        if ((err = ocb_encrypt_authenticate_memory(idx, tests[x].key, 16,
             tests[x].nonce, tests[x].pt, tests[x].ptlen, outct, outtag, &len)) != CRYPT_OK) {
           return err;
        }
        
        if (memcmp(outtag, tests[x].tag, len) || memcmp(outct, tests[x].ct, tests[x].ptlen)) {
#if 0
           unsigned long y;
           printf("\n\nFailure: \nCT:\n");
           for (y = 0; y < (unsigned long)tests[x].ptlen; ) {
               printf("0x%02x", outct[y]);
               if (y < (unsigned long)(tests[x].ptlen-1)) printf(", ");
               if (!(++y % 8)) printf("\n");
           }
           printf("\nTAG:\n");
           for (y = 0; y < len; ) {
               printf("0x%02x", outtag[y]);
               if (y < len-1) printf(", ");
               if (!(++y % 8)) printf("\n");
           }
#endif
           return CRYPT_FAIL_TESTVECTOR;
        }
        
        if ((err = ocb_decrypt_verify_memory(idx, tests[x].key, 16, tests[x].nonce, outct, tests[x].ptlen,
             outct, tests[x].tag, len, &res)) != CRYPT_OK) {
           return err;
        }
        if (res != 1 || memcmp(tests[x].pt, outct, tests[x].ptlen)) {
#if 0
           unsigned long y;
           printf("\n\nFailure-decrypt: \nPT:\n");
           for (y = 0; y < (unsigned long)tests[x].ptlen; ) {
               printf("0x%02x", outct[y]);
               if (y < (unsigned long)(tests[x].ptlen-1)) printf(", ");
               if (!(++y % 8)) printf("\n");
           }
           printf("\nres = %d\n\n", res);
#endif
        }
    }
    return CRYPT_OK;
#endif /* LTC_TEST */
}

#endif /* OCB_MODE */


/* some comments

   -- it's hard to seek
   -- hard to stream [you can't emit ciphertext until full block]
   -- The setup is somewhat complicated...
*/
