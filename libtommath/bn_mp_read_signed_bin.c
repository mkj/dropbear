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

/* read signed bin, big endian, first byte is 0==positive or 1==negative */
int
mp_read_signed_bin (mp_int * a, unsigned char *b, int c)
{
  int     res;

  if ((res = mp_read_unsigned_bin (a, b + 1, c - 1)) != MP_OKAY) {
    return res;
  }
  a->sign = ((b[0] == (unsigned char) 0) ? MP_ZPOS : MP_NEG);
  return MP_OKAY;
}
