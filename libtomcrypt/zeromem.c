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

void zeromem(void *dst, size_t len)
{
 unsigned char *mem = (unsigned char *)dst;
 _ARGCHK(dst != NULL);
 while (len-- > 0)
    *mem++ = 0;
}
