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

/* computes xR^-1 == x (mod N) via Montgomery Reduction */
int
mp_montgomery_reduce (mp_int * a, mp_int * m, mp_digit mp)
{
  int     ix, res, digs;
  mp_digit ui;

  /* can the fast reduction [comba] method be used?
   *
   * Note that unlike in mp_mul you're safely allowed *less*
   * than the available columns [255 per default] since carries
   * are fixed up in the inner loop.
   */
  digs = m->used * 2 + 1;
  if ((digs < MP_WARRAY)
      && m->used < (1 << ((CHAR_BIT * sizeof (mp_word)) - (2 * DIGIT_BIT)))) {
    return fast_mp_montgomery_reduce (a, m, mp);
  }

  /* grow the input as required */
  if (a->alloc < m->used * 2 + 1) {
    if ((res = mp_grow (a, m->used * 2 + 1)) != MP_OKAY) {
      return res;
    }
  }
  a->used = m->used * 2 + 1;

  for (ix = 0; ix < m->used; ix++) {
    /* ui = ai * m' mod b */
    ui = (a->dp[ix] * mp) & MP_MASK;

    /* a = a + ui * m * b^i */
    {
      register int iy;
      register mp_digit *tmpx, *tmpy, mu;
      register mp_word r;

      /* aliases */
      tmpx = m->dp;
      tmpy = a->dp + ix;

      mu = 0;
      for (iy = 0; iy < m->used; iy++) {
        r = ((mp_word) ui) * ((mp_word) * tmpx++) + ((mp_word) mu) + ((mp_word) * tmpy);
        mu = (r >> ((mp_word) DIGIT_BIT));
        *tmpy++ = (r & ((mp_word) MP_MASK));
      }
      /* propagate carries */
      while (mu) {
        *tmpy += mu;
        mu = (*tmpy >> DIGIT_BIT) & 1;
        *tmpy++ &= MP_MASK;
      }
    }
  }

  /* A = A/b^n */
  mp_rshd (a, m->used);

  /* if A >= m then A = A - m */
  if (mp_cmp_mag (a, m) != MP_LT) {
    return s_mp_sub (a, m, a);
  }

  return MP_OKAY;
}
