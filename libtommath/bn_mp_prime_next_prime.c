/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is library that provides for multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library is designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://math.libtomcrypt.org
 */
#include <tommath.h>

/* finds the next prime after the number "a" using "t" trials
 * of Miller-Rabin.
 */
int mp_prime_next_prime(mp_int *a, int t)
{
   int err, res;

   if (mp_iseven(a) == 1) {
      /* force odd */
      if ((err = mp_add_d(a, 1, a)) != MP_OKAY) {
         return err;
      }
   } else {
      /* force to next odd number */
      if ((err = mp_add_d(a, 2, a)) != MP_OKAY) {
         return err;
      }
   }

   for (;;) {
      /* is this prime? */
      if ((err = mp_prime_is_prime(a, t, &res)) != MP_OKAY) {
         return err;
      }

      if (res == 1) {
         break;
      }

      /* add two, next candidate */
      if ((err = mp_add_d(a, 2, a)) != MP_OKAY) {
         return err;
      }
   }

   return MP_OKAY;
}

