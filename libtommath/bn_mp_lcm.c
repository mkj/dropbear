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

/* computes least common multiple as a*b/(a, b) */
int
mp_lcm (mp_int * a, mp_int * b, mp_int * c)
{
  int     res;
  mp_int  t;


  if ((res = mp_init (&t)) != MP_OKAY) {
    return res;
  }

  if ((res = mp_mul (a, b, &t)) != MP_OKAY) {
    mp_clear (&t);
    return res;
  }

  if ((res = mp_gcd (a, b, c)) != MP_OKAY) {
    mp_clear (&t);
    return res;
  }

  res = mp_div (&t, c, c, NULL);
  mp_clear (&t);
  return res;
}
