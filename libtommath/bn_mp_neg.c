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

/* b = -a */
int
mp_neg (mp_int * a, mp_int * b)
{
  int     res;
  if ((res = mp_copy (a, b)) != MP_OKAY) {
    return res;
  }
  if (mp_iszero(b) != 1) {
     b->sign = (a->sign == MP_ZPOS) ? MP_NEG : MP_ZPOS;
  }
  return MP_OKAY;
}
