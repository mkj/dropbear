#include "tommath_private.h"
#ifdef BN_MP_LSHD_C
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

/* shift left a certain amount of digits */
int mp_lshd(mp_int *a, int b)
{
   int     x, res;

   /* if its less than zero return */
   if (b <= 0) {
      return MP_OKAY;
   }
   /* no need to shift 0 around */
   if (mp_iszero(a) == MP_YES) {
      return MP_OKAY;
   }

   /* grow to fit the new digits */
   if (a->alloc < (a->used + b)) {
      if ((res = mp_grow(a, a->used + b)) != MP_OKAY) {
         return res;
      }
   }

   {
      mp_digit *top, *bottom;

      /* increment the used by the shift amount then copy upwards */
      a->used += b;

      /* top */
      top = a->dp + a->used - 1;

      /* base */
      bottom = (a->dp + a->used - 1) - b;

      /* much like mp_rshd this is implemented using a sliding window
       * except the window goes the otherway around.  Copying from
       * the bottom to the top.  see bn_mp_rshd.c for more info.
       */
      for (x = a->used - 1; x >= b; x--) {
         *top-- = *bottom--;
      }

      /* zero the lower digits */
      top = a->dp;
      for (x = 0; x < b; x++) {
         *top++ = 0;
      }
   }
   return MP_OKAY;
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
