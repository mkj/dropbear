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

/* computes b = a*a */
int
mp_sqr (mp_int * a, mp_int * b)
{
  int     res;
#ifndef NO_LTM_TOOM
  if (a->used >= TOOM_SQR_CUTOFF) {
    res = mp_toom_sqr(a, b);
  } else
#endif
  if (a->used >= KARATSUBA_SQR_CUTOFF) {
    res = mp_karatsuba_sqr (a, b);
  } else {

    /* can we use the fast multiplier? */
    if ((a->used * 2 + 1) < MP_WARRAY && 
         a->used < 
         (1 << (sizeof(mp_word) * CHAR_BIT - 2*DIGIT_BIT - 1))) {
      res = fast_s_mp_sqr (a, b);
    } else {
      res = s_mp_sqr (a, b);
    }
  }
  b->sign = MP_ZPOS;
  return res;
}
