#include "tommath_private.h"
#ifdef BN_MP_MUL_2_C
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

/* b = a*2 */
int mp_mul_2(const mp_int *a, mp_int *b)
{
   int     x, res, oldused;

   /* grow to accomodate result */
   if (b->alloc < (a->used + 1)) {
      if ((res = mp_grow(b, a->used + 1)) != MP_OKAY) {
         return res;
      }
   }

   oldused = b->used;
   b->used = a->used;

   {
      mp_digit r, rr, *tmpa, *tmpb;

      /* alias for source */
      tmpa = a->dp;

      /* alias for dest */
      tmpb = b->dp;

      /* carry */
      r = 0;
      for (x = 0; x < a->used; x++) {

         /* get what will be the *next* carry bit from the
          * MSB of the current digit
          */
         rr = *tmpa >> (mp_digit)(DIGIT_BIT - 1);

         /* now shift up this digit, add in the carry [from the previous] */
         *tmpb++ = ((*tmpa++ << 1uL) | r) & MP_MASK;

         /* copy the carry that would be from the source
          * digit into the next iteration
          */
         r = rr;
      }

      /* new leading digit? */
      if (r != 0u) {
         /* add a MSB which is always 1 at this point */
         *tmpb = 1;
         ++(b->used);
      }

      /* now zero any excess digits on the destination
       * that we didn't write to
       */
      tmpb = b->dp + b->used;
      for (x = b->used; x < oldused; x++) {
         *tmpb++ = 0;
      }
   }
   b->sign = a->sign;
   return MP_OKAY;
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
