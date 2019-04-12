#include "tommath_private.h"
#ifdef BN_MP_ADD_C
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

/* high level addition (handles signs) */
int mp_add(const mp_int *a, const mp_int *b, mp_int *c)
{
   int     sa, sb, res;

   /* get sign of both inputs */
   sa = a->sign;
   sb = b->sign;

   /* handle two cases, not four */
   if (sa == sb) {
      /* both positive or both negative */
      /* add their magnitudes, copy the sign */
      c->sign = sa;
      res = s_mp_add(a, b, c);
   } else {
      /* one positive, the other negative */
      /* subtract the one with the greater magnitude from */
      /* the one of the lesser magnitude.  The result gets */
      /* the sign of the one with the greater magnitude. */
      if (mp_cmp_mag(a, b) == MP_LT) {
         c->sign = sb;
         res = s_mp_sub(b, a, c);
      } else {
         c->sign = sa;
         res = s_mp_sub(a, b, c);
      }
   }
   return res;
}

#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
