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

/* returns size of ASCII reprensentation */
int
mp_radix_size (mp_int * a, int radix)
{
  int     res, digs;
  mp_int  t;
  mp_digit d;

  /* special case for binary */
  if (radix == 2) {
    return mp_count_bits (a) + (a->sign == MP_NEG ? 1 : 0) + 1;
  }

  if (radix < 2 || radix > 64) {
    return 0;
  }

  if ((res = mp_init_copy (&t, a)) != MP_OKAY) {
    return 0;
  }

  digs = 0;
  if (t.sign == MP_NEG) {
    ++digs;
    t.sign = MP_ZPOS;
  }

  while (mp_iszero (&t) == 0) {
    if ((res = mp_div_d (&t, (mp_digit) radix, &t, &d)) != MP_OKAY) {
      mp_clear (&t);
      return 0;
    }
    ++digs;
  }
  mp_clear (&t);
  return digs + 1;
}

