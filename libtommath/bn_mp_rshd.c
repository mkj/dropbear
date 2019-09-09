#include "tommath_private.h"
#ifdef BN_MP_RSHD_C
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

/* shift right a certain amount of digits */
void mp_rshd(mp_int *a, int b)
{
   int     x;

   /* if b <= 0 then ignore it */
   if (b <= 0) {
      return;
   }

   /* if b > used then simply zero it and return */
   if (a->used <= b) {
      mp_zero(a);
      return;
   }

   {
      mp_digit *bottom, *top;

      /* shift the digits down */

      /* bottom */
      bottom = a->dp;

      /* top [offset into digits] */
      top = a->dp + b;

      /* this is implemented as a sliding window where
       * the window is b-digits long and digits from
       * the top of the window are copied to the bottom
       *
       * e.g.

       b-2 | b-1 | b0 | b1 | b2 | ... | bb |   ---->
                   /\                   |      ---->
                    \-------------------/      ---->
       */
      for (x = 0; x < (a->used - b); x++) {
         *bottom++ = *top++;
      }

      /* zero the top digits */
      for (; x < a->used; x++) {
         *bottom++ = 0;
      }
   }

   /* remove excess digits */
   a->used -= b;
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
