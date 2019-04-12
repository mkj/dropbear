#include "tommath_private.h"
#ifdef BN_MP_CMP_D_C
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

/* compare a digit */
int mp_cmp_d(const mp_int *a, mp_digit b)
{
   /* compare based on sign */
   if (a->sign == MP_NEG) {
      return MP_LT;
   }

   /* compare based on magnitude */
   if (a->used > 1) {
      return MP_GT;
   }

   /* compare the only digit of a to b */
   if (a->dp[0] > b) {
      return MP_GT;
   } else if (a->dp[0] < b) {
      return MP_LT;
   } else {
      return MP_EQ;
   }
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
