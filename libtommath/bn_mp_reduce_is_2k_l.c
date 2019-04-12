#include "tommath_private.h"
#ifdef BN_MP_REDUCE_IS_2K_L_C
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

/* determines if reduce_2k_l can be used */
int mp_reduce_is_2k_l(const mp_int *a)
{
   int ix, iy;

   if (a->used == 0) {
      return MP_NO;
   } else if (a->used == 1) {
      return MP_YES;
   } else if (a->used > 1) {
      /* if more than half of the digits are -1 we're sold */
      for (iy = ix = 0; ix < a->used; ix++) {
         if (a->dp[ix] == MP_MASK) {
            ++iy;
         }
      }
      return (iy >= (a->used/2)) ? MP_YES : MP_NO;

   }
   return MP_NO;
}

#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
