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

/* compare maginitude of two ints (unsigned) */
int
mp_cmp_mag (mp_int * a, mp_int * b)
{
  int     n;

  /* compare based on # of non-zero digits */
  if (a->used > b->used) {
    return MP_GT;
  } 
  
  if (a->used < b->used) {
    return MP_LT;
  }

  /* compare based on digits  */
  for (n = a->used - 1; n >= 0; n--) {
    if (a->dp[n] > b->dp[n]) {
      return MP_GT;
    } 
    
    if (a->dp[n] < b->dp[n]) {
      return MP_LT;
    }
  }
  return MP_EQ;
}
