#include "tommath_private.h"
#ifdef BN_MP_COUNT_BITS_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * SPDX-License-Identifier: Unlicense
 */

/* returns the number of bits in an int */
int mp_count_bits(const mp_int *a)
{
   int     r;
   mp_digit q;

   /* shortcut */
   if (a->used == 0) {
      return 0;
   }

   /* get number of digits and add that */
   r = (a->used - 1) * DIGIT_BIT;

   /* take the last digit and count the bits in it */
   q = a->dp[a->used - 1];
   while (q > (mp_digit)0) {
      ++r;
      q >>= (mp_digit)1;
   }
   return r;
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
