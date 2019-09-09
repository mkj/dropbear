#include "tommath_private.h"
#ifdef BN_MP_GET_LONG_C
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

/* get the lower unsigned long of an mp_int, platform dependent */
unsigned long mp_get_long(const mp_int *a)
{
   int i;
   unsigned long res;

   if (a->used == 0) {
      return 0;
   }

   /* get number of digits of the lsb we have to read */
   i = MIN(a->used, ((((int)sizeof(unsigned long) * CHAR_BIT) + DIGIT_BIT - 1) / DIGIT_BIT)) - 1;

   /* get most significant digit of result */
   res = DIGIT(a, i);

#if (ULONG_MAX != 0xffffffffuL) || (DIGIT_BIT < 32)
   while (--i >= 0) {
      res = (res << DIGIT_BIT) | DIGIT(a, i);
   }
#endif
   return res;
}
#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
