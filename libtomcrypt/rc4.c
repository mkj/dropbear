#include "mycrypt.h"

#ifdef RC4

const struct _prng_descriptor rc4_desc = 
{
   "rc4",
    &rc4_start,
    &rc4_add_entropy,
    &rc4_ready,
    &rc4_read
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
    _ARGCHK(buf != NULL);
    _ARGCHK(prng != NULL);

    if (prng->rc4.x + len > 256) {
       return CRYPT_INVALID_KEYSIZE;
    }

    while (len--) {
       prng->rc4.buf[prng->rc4.x++] = *buf++;
    }

    return CRYPT_OK;
    
}

int rc4_ready(prng_state *prng)
{
    unsigned char key[256], tmp;
    int keylen, x, y;

    _ARGCHK(prng != NULL);

    /* extract the key */
    memcpy(key, prng->rc4.buf, 256);
    keylen = prng->rc4.x;

    /* make RC4 perm and shuffle */
    for (x = 0; x < 256; x++) {
        prng->rc4.buf[x] = x;
    }

    for (x = y = 0; x < 256; x++) {
        y = (y + prng->rc4.buf[x] + key[x % keylen]) & 255;
        tmp = prng->rc4.buf[x]; prng->rc4.buf[x] = prng->rc4.buf[y]; prng->rc4.buf[y] = tmp;
    }
    prng->rc4.x = x;
    prng->rc4.y = y;

#ifdef CLEAN_STACK
    zeromem(key, sizeof(key));
#endif

    return CRYPT_OK;
}

unsigned long rc4_read(unsigned char *buf, unsigned long len, prng_state *prng)
{
   int x, y; 
   unsigned char *s, tmp;
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

#endif

