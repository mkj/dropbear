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

/* single digit addition */
int
mp_add_d (mp_int * a, mp_digit b, mp_int * c)
{
  mp_int  t;
  int     res;

  if ((res = mp_init_size(&t, 1)) != MP_OKAY) {
    return res;
  }
  mp_set (&t, b);
  res = mp_add (a, &t, c);

  mp_clear (&t);
  return res;
}
