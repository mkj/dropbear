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

/* this is a modified version of fast_s_mp_mul_digs that only produces
 * output digits *above* digs.  See the comments for fast_s_mp_mul_digs
 * to see how it works.
 *
 * This is used in the Barrett reduction since for one of the multiplications
 * only the higher digits were needed.  This essentially halves the work.
 *
 * Based on Algorithm 14.12 on pp.595 of HAC.
 */
int
fast_s_mp_mul_high_digs (mp_int * a, mp_int * b, mp_int * c, int digs)
{
  int     oldused, newused, res, pa, pb, ix;
  mp_word W[MP_WARRAY];

  /* calculate size of product and allocate more space if required */
  newused = a->used + b->used + 1;
  if (c->alloc < newused) {
    if ((res = mp_grow (c, newused)) != MP_OKAY) {
      return res;
    }
  }

  /* like the other comba method we compute the columns first */
  pa = a->used;
  pb = b->used;
  memset (W + digs, 0, (pa + pb + 1 - digs) * sizeof (mp_word));
  for (ix = 0; ix < pa; ix++) {
    {
      register mp_digit tmpx, *tmpy;
      register int iy;
      register mp_word *_W;

      /* work todo, that is we only calculate digits that are at "digs" or above  */
      iy = digs - ix;

      /* copy of word on the left of A[ix] * B[iy] */
      tmpx = a->dp[ix];

      /* alias for right side */
      tmpy = b->dp + iy;
     
      /* alias for the columns of output.  Offset to be equal to or above the 
       * smallest digit place requested 
       */
      _W = W + digs;     
      
      /* skip cases below zero where ix > digs */
      if (iy < 0) {
         iy    = abs(iy);
         tmpy += iy;
         _W   += iy;
         iy    = 0;
      }

      /* compute column products for digits above the minimum */
      for (; iy < pb; iy++) {
         *_W++ += ((mp_word) tmpx) * ((mp_word)*tmpy++);
      }
    }
  }

  /* setup dest */
  oldused = c->used;
  c->used = newused;

  /* now convert the array W downto what we need
   *
   * See comments in bn_fast_s_mp_mul_digs.c
   */
  for (ix = digs + 1; ix < newused; ix++) {
    W[ix] += (W[ix - 1] >> ((mp_word) DIGIT_BIT));
    c->dp[ix - 1] = (mp_digit) (W[ix - 1] & ((mp_word) MP_MASK));
  }
  c->dp[newused - 1] = (mp_digit) (W[newused - 1] & ((mp_word) MP_MASK));

  for (; ix < oldused; ix++) {
    c->dp[ix] = 0;
  }
  mp_clamp (c);
  return MP_OKAY;
}
