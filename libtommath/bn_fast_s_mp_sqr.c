/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://math.libtomcrypt.org
 */
#include <tommath.h>

/* fast squaring
 *
 * This is the comba method where the columns of the product 
 * are computed first then the carries are computed.  This 
 * has the effect of making a very simple inner loop that 
 * is executed the most
 *
 * W2 represents the outer products and W the inner.
 *
 * A further optimizations is made because the inner 
 * products are of the form "A * B * 2".  The *2 part does 
 * not need to be computed until the end which is good 
 * because 64-bit shifts are slow!
 *
 * Based on Algorithm 14.16 on pp.597 of HAC.
 *
 */
int
fast_s_mp_sqr (mp_int * a, mp_int * b)
{
  int     olduse, newused, res, ix, pa;
  mp_word W2[MP_WARRAY], W[MP_WARRAY];

  /* calculate size of product and allocate as required */
  pa = a->used;
  newused = pa + pa + 1;
  if (b->alloc < newused) {
    if ((res = mp_grow (b, newused)) != MP_OKAY) {
      return res;
    }
  }

  /* zero temp buffer (columns)
   * Note that there are two buffers.  Since squaring requires
   * a outer and inner product and the inner product requires
   * computing a product and doubling it (a relatively expensive
   * op to perform n**2 times if you don't have to) the inner and
   * outer products are computed in different buffers.  This way
   * the inner product can be doubled using n doublings instead of
   * n**2
   */
  memset (W,  0, newused * sizeof (mp_word));
  memset (W2, 0, newused * sizeof (mp_word));

  /* This computes the inner product.  To simplify the inner N**2 loop
   * the multiplication by two is done afterwards in the N loop.
   */
  for (ix = 0; ix < pa; ix++) {
    /* compute the outer product
     *
     * Note that every outer product is computed
     * for a particular column only once which means that
     * there is no need todo a double precision addition
     * into the W2[] array.
     */
    W2[ix + ix] = ((mp_word)a->dp[ix]) * ((mp_word)a->dp[ix]);

    {
      register mp_digit tmpx, *tmpy;
      register mp_word *_W;
      register int iy;

      /* copy of left side */
      tmpx = a->dp[ix];

      /* alias for right side */
      tmpy = a->dp + (ix + 1);

      /* the column to store the result in */
      _W = W + (ix + ix + 1);

      /* inner products */
      for (iy = ix + 1; iy < pa; iy++) {
          *_W++ += ((mp_word)tmpx) * ((mp_word)*tmpy++);
      }
    }
  }

  /* setup dest */
  olduse  = b->used;
  b->used = newused;

  /* now compute digits
   *
   * We have to double the inner product sums, add in the
   * outer product sums, propagate carries and convert
   * to single precision.
   */
  {
    register mp_digit *tmpb;

    /* double first value, since the inner products are 
     * half of what they should be 
     */
    W[0] += W[0] + W2[0];

    tmpb = b->dp;
    for (ix = 1; ix < newused; ix++) {
      /* double/add next digit */
      W[ix] += W[ix] + W2[ix];

      /* propagate carry forwards [from the previous digit] */
      W[ix] = W[ix] + (W[ix - 1] >> ((mp_word) DIGIT_BIT));

      /* store the current digit now that the carry isn't
       * needed
       */
      *tmpb++ = (mp_digit) (W[ix - 1] & ((mp_word) MP_MASK));
    }
    /* set the last value.  Note even if the carry is zero
     * this is required since the next step will not zero
     * it if b originally had a value at b->dp[2*a.used]
     */
    *tmpb++ = (mp_digit) (W[(newused) - 1] & ((mp_word) MP_MASK));

    /* clear high digits of b if there were any originally */
    for (; ix < olduse; ix++) {
      *tmpb++ = 0;
    }
  }

  mp_clamp (b);
  return MP_OKAY;
}
