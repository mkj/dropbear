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

/* compare two ints (signed)*/
int
mp_cmp (mp_int * a, mp_int * b)
{
  /* compare based on sign */
  if (a->sign == MP_NEG && b->sign == MP_ZPOS) {
    return MP_LT;
  } 
  
  if (a->sign == MP_ZPOS && b->sign == MP_NEG) {
    return MP_GT;
  }
  
  /* compare digits */
  if (a->sign == MP_NEG) {
     /* if negative compare opposite direction */
     return mp_cmp_mag(b, a);
  } else {
     return mp_cmp_mag(a, b);
  }
}
