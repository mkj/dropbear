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

/* A secure PRNG using the RNG functions.  Basically this is a
 * wrapper that allows you to use a secure RNG as a PRNG
 * in the various other functions.
 */
#include "mycrypt.h"

#ifdef SPRNG

const struct _prng_descriptor sprng_desc =
{
    "sprng",
    &sprng_start,
    &sprng_add_entropy,
    &sprng_ready,
    &sprng_read
};

int sprng_start(prng_state *prng)
{
   return CRYPT_OK;  
}

int sprng_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng)
{
   return CRYPT_OK;
}

int sprng_ready(prng_state *prng)
{
   return CRYPT_OK;
}

unsigned long sprng_read(unsigned char *buf, unsigned long len, prng_state *prng)
{
   _ARGCHK(buf != NULL);
   return rng_get_bytes(buf, len, NULL);
}

#endif


 
