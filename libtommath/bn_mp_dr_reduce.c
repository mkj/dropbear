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

/* reduce "a" in place modulo "b" using the Diminished Radix algorithm.
 *
 * Based on algorithm from the paper
 *
 * "Generating Efficient Primes for Discrete Log Cryptosystems"
 *                 Chae Hoon Lim, Pil Loong Lee,
 *          POSTECH Information Research Laboratories
 *
 * The modulus must be of a special format [see manual]
 */
int
mp_dr_reduce (mp_int * a, mp_int * b, mp_digit mp)
{
  int     err, i, j, k;
  mp_word r;
  mp_digit mu, *tmpj, *tmpi;

  /* k = digits in modulus */
  k = b->used;

  /* ensure that "a" has at least 2k digits */
  if (a->alloc < k + k) {
    if ((err = mp_grow (a, k + k)) != MP_OKAY) {
      return err;
    }
  }

  /* alias for a->dp[i] */
  tmpi = a->dp + k + k - 1;

  /* for (i = 2k - 1; i >= k; i = i - 1)
   *
   * This is the main loop of the reduction.  Note that at the end
   * the words above position k are not zeroed as expected.  The end
   * result is that the digits from 0 to k-1 are the residue.  So
   * we have to clear those afterwards.
   */
  for (i = k + k - 1; i >= k; i = i - 1) {
    /* x[i - 1 : i - k] += x[i]*mp */

    /* x[i] * mp */
    r = ((mp_word) *tmpi--) * ((mp_word) mp);

    /* now add r to x[i-1:i-k]
     *
     * First add it to the first digit x[i-k] then form the carry
     * then enter the main loop
     */
    j = i - k;

    /* alias for a->dp[j] */
    tmpj = a->dp + j;

    /* add digit */
    *tmpj += (mp_digit)(r & MP_MASK);

    /* this is the carry */
    mu = (r >> ((mp_word) DIGIT_BIT)) + (*tmpj >> DIGIT_BIT);

    /* clear carry from a->dp[j]  */
    *tmpj++ &= MP_MASK;

    /* now add rest of the digits
     *
     * Note this is basically a simple single digit addition to
     * a larger multiple digit number.  This is optimized somewhat
     * because the propagation of carries is not likely to move
     * more than a few digits.
     *
     */
    for (++j; mu != 0 && j <= (i - 1); ++j) {
      *tmpj   += mu;
      mu       = *tmpj >> DIGIT_BIT;
      *tmpj++ &= MP_MASK;
    }

    /* if final carry */
    if (mu != 0) {
      /* add mp to this to correct */
      j = i - k;
      tmpj = a->dp + j;

      *tmpj += mp;
      mu = *tmpj >> DIGIT_BIT;
      *tmpj++ &= MP_MASK;

      /* now handle carries */
      for (++j; mu != 0 && j <= (i - 1); j++) {
          *tmpj   += mu;
          mu       = *tmpj >> DIGIT_BIT;
          *tmpj++ &= MP_MASK;
      }
    }
  }

  /* zero words above k */
  tmpi = a->dp + k;
  for (i = k; i < a->used; i++) {
      *tmpi++ = 0;
  }

  /* clamp, sub and return */
  mp_clamp (a);

  /* if a >= b [b == modulus] then subtract the modulus to fix up */
  if (mp_cmp_mag (a, b) != MP_LT) {
    return s_mp_sub (a, b, a);
  }
  return MP_OKAY;
}



