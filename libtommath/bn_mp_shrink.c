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

/* shrink a bignum */
int
mp_shrink (mp_int * a)
{
  if (a->alloc != a->used) {
    if ((a->dp = OPT_CAST realloc (a->dp, sizeof (mp_digit) * a->used)) == NULL) {
      return MP_MEM;
    }
    a->alloc = a->used;
  }
  return MP_OKAY;
}
