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

/* Fast (comba) multiplier
 *
 * This is the fast column-array [comba] multiplier.  It is 
 * designed to compute the columns of the product first 
 * then handle the carries afterwards.  This has the effect 
 * of making the nested loops that compute the columns very
 * simple and schedulable on super-scalar processors.
 *
 * This has been modified to produce a variable number of 
 * digits of output so if say only a half-product is required 
 * you don't have to compute the upper half (a feature 
 * required for fast Barrett reduction).
 *
 * Based on Algorithm 14.12 on pp.595 of HAC.
 *
 */
int
fast_s_mp_mul_digs (mp_int * a, mp_int * b, mp_int * c, int digs)
{
  int     olduse, res, pa, ix;
  mp_word W[MP_WARRAY];

  /* grow the destination as required */
  if (c->alloc < digs) {
    if ((res = mp_grow (c, digs)) != MP_OKAY) {
      return res;
    }
  }

  /* clear temp buf (the columns) */
  memset (W, 0, sizeof (mp_word) * digs);

  /* calculate the columns */
  pa = a->used;
  for (ix = 0; ix < pa; ix++) {
    /* this multiplier has been modified to allow you to 
     * control how many digits of output are produced.  
     * So at most we want to make upto "digs" digits of output.
     *
     * this adds products to distinct columns (at ix+iy) of W
     * note that each step through the loop is not dependent on
     * the previous which means the compiler can easily unroll
     * the loop without scheduling problems
     */
    {
      register mp_digit tmpx, *tmpy;
      register mp_word *_W;
      register int iy, pb;

      /* alias for the the word on the left e.g. A[ix] * A[iy] */
      tmpx = a->dp[ix];

      /* alias for the right side */
      tmpy = b->dp;

      /* alias for the columns, each step through the loop adds a new
         term to each column
       */
      _W = W + ix;

      /* the number of digits is limited by their placement.  E.g.
         we avoid multiplying digits that will end up above the # of
         digits of precision requested
       */
      pb = MIN (b->used, digs - ix);

      for (iy = 0; iy < pb; iy++) {
        *_W++ += ((mp_word)tmpx) * ((mp_word)*tmpy++);
      }
    }

  }

  /* setup dest */
  olduse = c->used;
  c->used = digs;

  {
    register mp_digit *tmpc;

    /* At this point W[] contains the sums of each column.  To get the
     * correct result we must take the extra bits from each column and
     * carry them down
     *
     * Note that while this adds extra code to the multiplier it 
     * saves time since the carry propagation is removed from the 
     * above nested loop.This has the effect of reducing the work 
     * from N*(N+N*c)==N**2 + c*N**2 to N**2 + N*c where c is the 
     * cost of the shifting.  On very small numbers this is slower 
     * but on most cryptographic size numbers it is faster.
     *
     * In this particular implementation we feed the carries from
     * behind which means when the loop terminates we still have one
     * last digit to copy
     */
    tmpc = c->dp;
    for (ix = 1; ix < digs; ix++) {
      /* forward the carry from the previous temp */
      W[ix] += (W[ix - 1] >> ((mp_word) DIGIT_BIT));

      /* now extract the previous digit [below the carry] */
      *tmpc++ = (mp_digit) (W[ix - 1] & ((mp_word) MP_MASK));
    }
    /* fetch the last digit */
    *tmpc++ = (mp_digit) (W[digs - 1] & ((mp_word) MP_MASK));

    /* clear unused digits [that existed in the old copy of c] */
    for (; ix < olduse; ix++) {
      *tmpc++ = 0;
    }
  }
  mp_clamp (c);
  return MP_OKAY;
}
