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

/* single digit division (based on routine from MPI) */
int
mp_div_d (mp_int * a, mp_digit b, mp_int * c, mp_digit * d)
{
  mp_int  q;
  mp_word w;
  mp_digit t;
  int     res, ix;
  
  if (b == 0) {
     return MP_VAL;
  }
  
  if (b == 3) {
     return mp_div_3(a, c, d);
  }
  
  if ((res = mp_init_size(&q, a->used)) != MP_OKAY) {
     return res;
  }
  
  q.used = a->used;
  q.sign = a->sign;
  w = 0;
  for (ix = a->used - 1; ix >= 0; ix--) {
     w = (w << ((mp_word)DIGIT_BIT)) | ((mp_word)a->dp[ix]);
     
     if (w >= b) {
        t = (mp_digit)(w / b);
        w = w % b;
      } else {
        t = 0;
      }
      q.dp[ix] = (mp_digit)t;
  }
  
  if (d != NULL) {
     *d = (mp_digit)w;
  }
  
  if (c != NULL) {
     mp_clamp(&q);
     mp_exch(&q, c);
  }
  mp_clear(&q);
  
  return res;
}

