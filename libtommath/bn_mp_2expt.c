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

/* computes a = 2**b 
 *
 * Simple algorithm which zeroes the int, grows it then just sets one bit
 * as required.
 */
int
mp_2expt (mp_int * a, int b)
{
  int     res;

  mp_zero (a);
  if ((res = mp_grow (a, b / DIGIT_BIT + 1)) != MP_OKAY) {
    return res;
  }
  a->used = b / DIGIT_BIT + 1;
  a->dp[b / DIGIT_BIT] = 1 << (b % DIGIT_BIT);

  return MP_OKAY;
}
