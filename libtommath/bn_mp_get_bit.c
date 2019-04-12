#include "tommath_private.h"
#ifdef BN_MP_GET_BIT_C

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

/* Checks the bit at position b and returns MP_YES
   if the bit is 1, MP_NO if it is 0 and MP_VAL
   in case of error */
int mp_get_bit(const mp_int *a, int b)
{
   int limb;
   mp_digit bit, isset;

   if (b < 0) {
      return MP_VAL;
   }

   limb = b / DIGIT_BIT;

   /*
    * Zero is a special value with the member "used" set to zero.
    * Needs to be tested before the check for the upper boundary
    * otherwise (limb >= a->used) would be true for a = 0
    */

   if (mp_iszero(a) != MP_NO) {
      return MP_NO;
   }

   if (limb >= a->used) {
      return MP_VAL;
   }

   bit = (mp_digit)(1) << (b % DIGIT_BIT);

   isset = a->dp[limb] & bit;
   return (isset != 0u) ? MP_YES : MP_NO;
}

#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
