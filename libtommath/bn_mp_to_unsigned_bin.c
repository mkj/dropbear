#include "tommath_private.h"
#ifdef BN_MP_TO_UNSIGNED_BIN_C
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

/* store in unsigned [big endian] format */
int mp_to_unsigned_bin(const mp_int *a, unsigned char *b)
{
   int     x, res;
   mp_int  t;

   if ((res = mp_init_copy(&t, a)) != MP_OKAY) {
      return res;
   }

   x = 0;
   while (mp_iszero(&t) == MP_NO) {
#ifndef MP_8BIT
      b[x++] = (unsigned char)(t.dp[0] & 255u);
#else
      b[x++] = (unsigned char)(t.dp[0] | ((t.dp[1] & 1u) << 7));
#endif
      if ((res = mp_div_2d(&t, 8, &t, NULL)) != MP_OKAY) {
         mp_clear(&t);
         return res;
      }
   }
   bn_reverse(b, x);
   mp_clear(&t);
   return MP_OKAY;
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
