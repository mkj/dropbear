/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://math.libtomcrypt.org
 */
#include <tommath.h>

/* performs a variable number of rounds of Miller-Rabin
 *
 * Probability of error after t rounds is no more than
 * (1/4)^t when 1 <= t <= PRIME_SIZE
 *
 * Sets result to 1 if probably prime, 0 otherwise
 */
int mp_prime_is_prime (mp_int * a, int t, int *result)
{
  mp_int  b;
  int     ix, err, res;

  /* default to no */
  *result = MP_NO;

  /* valid value of t? */
  if (t <= 0 || t > PRIME_SIZE) {
    return MP_VAL;
  }

  /* is the input equal to one of the primes in the table? */
  for (ix = 0; ix < PRIME_SIZE; ix++) {
      if (mp_cmp_d(a, __prime_tab[ix]) == MP_EQ) {
         *result = 1;
         return MP_OKAY;
      }
  }

  /* first perform trial division */
  if ((err = mp_prime_is_divisible (a, &res)) != MP_OKAY) {
    return err;
  }

  /* return if it was trivially divisible */
  if (res == MP_YES) {
    return MP_OKAY;
  }

  /* now perform the miller-rabin rounds */
  if ((err = mp_init (&b)) != MP_OKAY) {
    return err;
  }

  for (ix = 0; ix < t; ix++) {
    /* set the prime */
    mp_set (&b, __prime_tab[ix]);

    if ((err = mp_prime_miller_rabin (a, &b, &res)) != MP_OKAY) {
      goto __B;
    }

    if (res == MP_NO) {
      goto __B;
    }
  }

  /* passed the test */
  *result = MP_YES;
__B:mp_clear (&b);
  return err;
}
