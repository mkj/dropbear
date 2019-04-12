#include "tommath_private.h"
#ifdef BN_MP_KRONECKER_C

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

/*
   Kronecker symbol (a|p)
   Straightforward implementation of algorithm 1.4.10 in
   Henri Cohen: "A Course in Computational Algebraic Number Theory"

   @book{cohen2013course,
     title={A course in computational algebraic number theory},
     author={Cohen, Henri},
     volume={138},
     year={2013},
     publisher={Springer Science \& Business Media}
    }
 */
int mp_kronecker(const mp_int *a, const mp_int *p, int *c)
{
   mp_int a1, p1, r;

   int e = MP_OKAY;
   int v, k;

   static const int table[8] = {0, 1, 0, -1, 0, -1, 0, 1};

   if (mp_iszero(p) != MP_NO) {
      if ((a->used == 1) && (a->dp[0] == 1u)) {
         *c = 1;
         return e;
      } else {
         *c = 0;
         return e;
      }
   }

   if ((mp_iseven(a) != MP_NO) && (mp_iseven(p) != MP_NO)) {
      *c = 0;
      return e;
   }

   if ((e = mp_init_copy(&a1, a)) != MP_OKAY) {
      return e;
   }
   if ((e = mp_init_copy(&p1, p)) != MP_OKAY) {
      goto LBL_KRON_0;
   }

   v = mp_cnt_lsb(&p1);
   if ((e = mp_div_2d(&p1, v, &p1, NULL)) != MP_OKAY) {
      goto LBL_KRON_1;
   }

   if ((v & 0x1) == 0) {
      k = 1;
   } else {
      k = table[a->dp[0] & 7u];
   }

   if (p1.sign == MP_NEG) {
      p1.sign = MP_ZPOS;
      if (a1.sign == MP_NEG) {
         k = -k;
      }
   }

   if ((e = mp_init(&r)) != MP_OKAY) {
      goto LBL_KRON_1;
   }

   for (;;) {
      if (mp_iszero(&a1) != MP_NO) {
         if (mp_cmp_d(&p1, 1uL) == MP_EQ) {
            *c = k;
            goto LBL_KRON;
         } else {
            *c = 0;
            goto LBL_KRON;
         }
      }

      v = mp_cnt_lsb(&a1);
      if ((e = mp_div_2d(&a1, v, &a1, NULL)) != MP_OKAY) {
         goto LBL_KRON;
      }

      if ((v & 0x1) == 1) {
         k = k * table[p1.dp[0] & 7u];
      }

      if (a1.sign == MP_NEG) {
         /*
          * Compute k = (-1)^((a1)*(p1-1)/4) * k
          * a1.dp[0] + 1 cannot overflow because the MSB
          * of the type mp_digit is not set by definition
          */
         if (((a1.dp[0] + 1u) & p1.dp[0] & 2u) != 0u) {
            k = -k;
         }
      } else {
         /* compute k = (-1)^((a1-1)*(p1-1)/4) * k */
         if ((a1.dp[0] & p1.dp[0] & 2u) != 0u) {
            k = -k;
         }
      }

      if ((e = mp_copy(&a1, &r)) != MP_OKAY) {
         goto LBL_KRON;
      }
      r.sign = MP_ZPOS;
      if ((e = mp_mod(&p1, &r, &a1)) != MP_OKAY) {
         goto LBL_KRON;
      }
      if ((e = mp_copy(&r, &p1)) != MP_OKAY) {
         goto LBL_KRON;
      }
   }

LBL_KRON:
   mp_clear(&r);
LBL_KRON_1:
   mp_clear(&p1);
LBL_KRON_0:
   mp_clear(&a1);

   return e;
}

#endif

/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
