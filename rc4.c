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
#include "mycrypt.h"

#ifdef RC4

const struct _prng_descriptor rc4_desc = 
{
   "rc4", 32,
    &rc4_start,
    &rc4_add_entropy,
    &rc4_ready,
    &rc4_read,
    &rc4_done,
    &rc4_export,
    &rc4_import,
    &rc4_test
};

int rc4_start(prng_state *prng)
{
    _ARGCHK(prng != NULL);

    /* set keysize to zero */
    prng->rc4.x = 0;
    
    return CRYPT_OK;
}

int rc4_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng)
{
    _ARGCHK(buf  != NULL);
    _ARGCHK(prng != NULL);
 
    /* trim as required */
    if (prng->rc4.x + len > 256) {
       if (prng->rc4.x == 256) {
          /* I can't possibly accept another byte, ok maybe a mint wafer... */
          return CRYPT_OK;
       } else {
          /* only accept part of it */
          len = 256 - prng->rc4.x;
       }       
    }

    while (len--) {
       prng->rc4.buf[prng->rc4.x++] = *buf++;
    }

    return CRYPT_OK;
    
}

int rc4_ready(prng_state *prng)
{
    unsigned char key[256], tmp, *s;
    int keylen, x, y, j;

    _ARGCHK(prng != NULL);

    /* extract the key */
    s = prng->rc4.buf;
    XMEMCPY(key, s, 256);
    keylen = prng->rc4.x;

    /* make RC4 perm and shuffle */
    for (x = 0; x < 256; x++) {
        s[x] = x;
    }

    for (j = x = y = 0; x < 256; x++) {
        y = (y + prng->rc4.buf[x] + key[j++]) & 255;
        if (j == keylen) {
           j = 0; 
        }
        tmp = s[x]; s[x] = s[y]; s[y] = tmp;
    }
    prng->rc4.x = 0;
    prng->rc4.y = 0;

#ifdef CLEAN_STACK
    zeromem(key, sizeof(key));
#endif

    return CRYPT_OK;
}

unsigned long rc4_read(unsigned char *buf, unsigned long len, prng_state *prng)
{
   unsigned char x, y, *s, tmp;
   unsigned long n;

   _ARGCHK(buf != NULL);
   _ARGCHK(prng != NULL);

   n = len;
   x = prng->rc4.x;
   y = prng->rc4.y;
   s = prng->rc4.buf;
   while (len--) {
      x = (x + 1) & 255;
      y = (y + s[x]) & 255;
      tmp = s[x]; s[x] = s[y]; s[y] = tmp;
      tmp = (s[x] + s[y]) & 255;
      *buf++ ^= s[tmp];
   }
   prng->rc4.x = x;
   prng->rc4.y = y;
   return n;
}

int rc4_done(prng_state *prng)
{
   _ARGCHK(prng != NULL);
   return CRYPT_OK;
}

int rc4_export(unsigned char *out, unsigned long *outlen, prng_state *prng)
{
   _ARGCHK(outlen != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(prng   != NULL);

   if (*outlen < 32) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (rc4_read(out, 32, prng) != 32) {
      return CRYPT_ERROR_READPRNG;
   }
   *outlen = 32;

   return CRYPT_OK;
}
 
int rc4_import(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   int err;
   _ARGCHK(in   != NULL);
   _ARGCHK(prng != NULL);

   if (inlen != 32) {
      return CRYPT_INVALID_ARG;
   }
   
   if ((err = rc4_start(prng)) != CRYPT_OK) {
      return err;
   }
   return rc4_add_entropy(in, 32, prng);
}

int rc4_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
      unsigned char key[8], pt[8], ct[8];
   } tests[] = {
{
   { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
   { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
   { 0x75, 0xb7, 0x87, 0x80, 0x99, 0xe0, 0xc5, 0x96 }
}
};
   prng_state prng;
   unsigned char dst[8];
   int err, x;

   for (x = 0; x < (int)(sizeof(tests)/sizeof(tests[0])); x++) {
       if ((err = rc4_start(&prng)) != CRYPT_OK) {
          return err;
       }
       if ((err = rc4_add_entropy(tests[x].key, 8, &prng)) != CRYPT_OK) {
          return err;
       }
       if ((err = rc4_ready(&prng)) != CRYPT_OK) {
          return err;
       }
       XMEMCPY(dst, tests[x].pt, 8);
       if (rc4_read(dst, 8, &prng) != 8) {
          return CRYPT_ERROR_READPRNG;
       }
       rc4_done(&prng);
       if (memcmp(dst, tests[x].ct, 8)) {
#if 0
          int y;
          printf("\n\nRC4 failed, I got:\n"); 
          for (y = 0; y < 8; y++) printf("%02x ", dst[y]);
          printf("\n");
#endif
          return CRYPT_FAIL_TESTVECTOR;
       }
   }
   return CRYPT_OK;
#endif
}

#endif

