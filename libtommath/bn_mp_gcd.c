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

/* Greatest Common Divisor using the binary method [Algorithm B, page 338, vol2 of TAOCP]
 */
int
mp_gcd (mp_int * a, mp_int * b, mp_int * c)
{
  mp_int  u, v, t;
  int     k, res, neg;

  /* either zero than gcd is the largest */
  if (mp_iszero (a) == 1 && mp_iszero (b) == 0) {
    return mp_copy (b, c);
  }
  if (mp_iszero (a) == 0 && mp_iszero (b) == 1) {
    return mp_copy (a, c);
  }
  if (mp_iszero (a) == 1 && mp_iszero (b) == 1) {
    mp_set (c, 1);
    return MP_OKAY;
  }

  /* if both are negative they share (-1) as a common divisor */
  neg = (a->sign == b->sign) ? a->sign : MP_ZPOS;

  if ((res = mp_init_copy (&u, a)) != MP_OKAY) {
    return res;
  }

  if ((res = mp_init_copy (&v, b)) != MP_OKAY) {
    goto __U;
  }

  /* must be positive for the remainder of the algorithm */
  u.sign = v.sign = MP_ZPOS;

  if ((res = mp_init (&t)) != MP_OKAY) {
    goto __V;
  }

  /* B1.  Find power of two */
  k = 0;
  while (mp_iseven(&u) == 1 && mp_iseven(&v) == 1) {
    ++k;
    if ((res = mp_div_2 (&u, &u)) != MP_OKAY) {
      goto __T;
    }
    if ((res = mp_div_2 (&v, &v)) != MP_OKAY) {
      goto __T;
    }
  }

  /* B2.  Initialize */
  if (mp_isodd(&u) == 1) {
    /* t = -v */
    if ((res = mp_copy (&v, &t)) != MP_OKAY) {
      goto __T;
    }
    t.sign = MP_NEG;
  } else {
    /* t = u */
    if ((res = mp_copy (&u, &t)) != MP_OKAY) {
      goto __T;
    }
  }

  do {
    /* B3 (and B4).  Halve t, if even */
    while (t.used != 0 && mp_iseven(&t) == 1) {
      if ((res = mp_div_2 (&t, &t)) != MP_OKAY) {
        goto __T;
      }
    }

    /* B5.  if t>0 then u=t otherwise v=-t */
    if (t.used != 0 && t.sign != MP_NEG) {
      if ((res = mp_copy (&t, &u)) != MP_OKAY) {
        goto __T;
      }
    } else {
      if ((res = mp_copy (&t, &v)) != MP_OKAY) {
        goto __T;
      }
      v.sign = (v.sign == MP_ZPOS) ? MP_NEG : MP_ZPOS;
    }

    /* B6.  t = u - v, if t != 0 loop otherwise terminate */
    if ((res = mp_sub (&u, &v, &t)) != MP_OKAY) {
      goto __T;
    }
  } while (mp_iszero(&t) == 0);

  /* multiply by 2^k which we divided out at the beginning */ 
  if ((res = mp_mul_2d (&u, k, &u)) != MP_OKAY) {
    goto __T;
  }

  mp_exch (&u, c);
  c->sign = neg;
  res = MP_OKAY;
__T:mp_clear (&t);
__V:mp_clear (&u);
__U:mp_clear (&v);
  return res;
}
