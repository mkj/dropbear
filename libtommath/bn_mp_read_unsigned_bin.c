/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is library that provides for multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library is designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://math.libtomcrypt.org
 */
#include <tommath.h>

/* reads a unsigned char array, assumes the msb is stored first [big endian] */
int
mp_read_unsigned_bin (mp_int * a, unsigned char *b, int c)
{
  int     res;
  mp_zero (a);
  while (c-- > 0) {
    if ((res = mp_mul_2d (a, 8, a)) != MP_OKAY) {
      return res;
    }

    if (DIGIT_BIT != 7) {
      a->dp[0] |= *b++;
      a->used += 1;
    } else {
      a->dp[0] = (*b & MP_MASK);
      a->dp[1] |= ((*b++ >> 7U) & 1);
      a->used += 2;
    }
  }
  mp_clamp (a);
  return MP_OKAY;
}
