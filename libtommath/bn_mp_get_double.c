#include "tommath_private.h"
#ifdef BN_MP_GET_DOUBLE_C
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

double mp_get_double(const mp_int *a)
{
   int i;
   double d = 0.0, fac = 1.0;
   for (i = 0; i < DIGIT_BIT; ++i) {
      fac *= 2.0;
   }
   for (i = USED(a); i --> 0;) {
      d = (d * fac) + (double)DIGIT(a, i);
   }
   return (mp_isneg(a) != MP_NO) ? -d : d;
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
