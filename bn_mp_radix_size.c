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
int mp_radix_size (mp_int * a, int radix, int *size)
{
  int     res, digs;
  mp_int  t;
  mp_digit d;

  *size = 0;

  /* special case for binary */
  if (radix == 2) {
    *size = mp_count_bits (a) + (a->sign == MP_NEG ? 1 : 0) + 1;
    return MP_OKAY;
  }

  /* make sure the radix is in range */
  if (radix < 2 || radix > 64) {
    return MP_VAL;
  }

  /* init a copy of the input */
  if ((res = mp_init_copy (&t, a)) != MP_OKAY) {
    return res;
  }

  /* digs is the digit count */
  digs = 0;

  /* if it's negative add one for the sign */
  if (t.sign == MP_NEG) {
    ++digs;
    t.sign = MP_ZPOS;
  }

  /* fetch out all of the digits */
  while (mp_iszero (&t) == 0) {
    if ((res = mp_div_d (&t, (mp_digit) radix, &t, &d)) != MP_OKAY) {
      mp_clear (&t);
      return res;
    }
    ++digs;
  }
  mp_clear (&t);

  /* return digs + 1, the 1 is for the NULL byte that would be required. */
  *size = digs + 1;
  return MP_OKAY;
}

