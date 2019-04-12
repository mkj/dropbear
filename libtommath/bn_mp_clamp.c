#include "tommath_private.h"
#ifdef BN_MP_CLAMP_C
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

/* trim unused digits
 *
 * This is used to ensure that leading zero digits are
 * trimed and the leading "used" digit will be non-zero
 * Typically very fast.  Also fixes the sign if there
 * are no more leading digits
 */
void mp_clamp(mp_int *a)
{
   /* decrease used while the most significant digit is
    * zero.
    */
   while ((a->used > 0) && (a->dp[a->used - 1] == 0u)) {
      --(a->used);
   }

   /* reset the sign flag if used == 0 */
   if (a->used == 0) {
      a->sign = MP_ZPOS;
   }
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
