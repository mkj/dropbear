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

int
mp_mod_d (mp_int * a, mp_digit b, mp_digit * c)
{
  mp_int  t, t2;
  int     res;


  if ((res = mp_init (&t)) != MP_OKAY) {
    return res;
  }

  if ((res = mp_init (&t2)) != MP_OKAY) {
    mp_clear (&t);
    return res;
  }

  mp_set (&t, b);
  mp_div (a, &t, NULL, &t2);

  if (t2.sign == MP_NEG) {
    if ((res = mp_add_d (&t2, b, &t2)) != MP_OKAY) {
      mp_clear (&t);
      mp_clear (&t2);
      return res;
    }
  }
  *c = t2.dp[0];
  mp_clear (&t);
  mp_clear (&t2);
  return MP_OKAY;
}
