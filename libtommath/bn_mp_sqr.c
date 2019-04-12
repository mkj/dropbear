#include "tommath_private.h"
#ifdef BN_MP_SQR_C
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

/* computes b = a*a */
int mp_sqr(const mp_int *a, mp_int *b)
{
   int     res;

#ifdef BN_MP_TOOM_SQR_C
   /* use Toom-Cook? */
   if (a->used >= TOOM_SQR_CUTOFF) {
      res = mp_toom_sqr(a, b);
      /* Karatsuba? */
   } else
#endif
#ifdef BN_MP_KARATSUBA_SQR_C
      if (a->used >= KARATSUBA_SQR_CUTOFF) {
         res = mp_karatsuba_sqr(a, b);
      } else
#endif
      {
#ifdef BN_FAST_S_MP_SQR_C
         /* can we use the fast comba multiplier? */
         if ((((a->used * 2) + 1) < (int)MP_WARRAY) &&
             (a->used <
              (int)(1u << (((sizeof(mp_word) * (size_t)CHAR_BIT) - (2u * (size_t)DIGIT_BIT)) - 1u)))) {
            res = fast_s_mp_sqr(a, b);
         } else
#endif
         {
#ifdef BN_S_MP_SQR_C
            res = s_mp_sqr(a, b);
#else
            res = MP_VAL;
#endif
         }
      }
   b->sign = MP_ZPOS;
   return res;
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
