#include "tommath_private.h"
#ifdef BN_MP_ZERO_C
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

/* set to zero */
void mp_zero(mp_int *a)
{
   int       n;
   mp_digit *tmp;

   a->sign = MP_ZPOS;
   a->used = 0;

   tmp = a->dp;
   for (n = 0; n < a->alloc; n++) {
      *tmp++ = 0;
   }
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
