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

static int f_mp_exptmod (mp_int * G, mp_int * X, mp_int * P, mp_int * Y);

/* this is a shell function that calls either the normal or Montgomery
 * exptmod functions.  Originally the call to the montgomery code was
 * embedded in the normal function but that wasted alot of stack space
 * for nothing (since 99% of the time the Montgomery code would be called)
 */
int
mp_exptmod (mp_int * G, mp_int * X, mp_int * P, mp_int * Y)
{
  int dr;

  /* modulus P must be positive */
  if (P->sign == MP_NEG) {
     return MP_VAL;
  }

  /* if exponent X is negative we have to recurse */
  if (X->sign == MP_NEG) {
     mp_int tmpG, tmpX;
     int err;

     /* first compute 1/G mod P */
     if ((err = mp_init(&tmpG)) != MP_OKAY) {
        return err;
     }
     if ((err = mp_invmod(G, P, &tmpG)) != MP_OKAY) {
        mp_clear(&tmpG);
        return err;
     }

     /* now get |X| */
     if ((err = mp_init(&tmpX)) != MP_OKAY) {
        mp_clear(&tmpG);
        return err;
     }
     if ((err = mp_abs(X, &tmpX)) != MP_OKAY) {
        mp_clear_multi(&tmpG, &tmpX, NULL);
        return err;
     }

     /* and now compute (1/G)^|X| instead of G^X [X < 0] */
     err = mp_exptmod(&tmpG, &tmpX, P, Y);
     mp_clear_multi(&tmpG, &tmpX, NULL);
     return err;
  }


  dr = mp_dr_is_modulus(P);
  /* if the modulus is odd use the fast method */
  if ((mp_isodd (P) == 1 || dr == 1) && P->used > 4) {
    return mp_exptmod_fast (G, X, P, Y, dr);
  } else {
    return f_mp_exptmod (G, X, P, Y);
  }
}

static int
f_mp_exptmod (mp_int * G, mp_int * X, mp_int * P, mp_int * Y)
{
  mp_int  M[256], res, mu;
  mp_digit buf;
  int     err, bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;

  /* find window size */
  x = mp_count_bits (X);
  if (x <= 7) {
    winsize = 2;
  } else if (x <= 36) {
    winsize = 3;
  } else if (x <= 140) {
    winsize = 4;
  } else if (x <= 450) {
    winsize = 5;
  } else if (x <= 1303) {
    winsize = 6;
  } else if (x <= 3529) {
    winsize = 7;
  } else {
    winsize = 8;
  }

#ifdef MP_LOW_MEM
    if (winsize > 5) {
       winsize = 5;
    }
#endif

  /* init G array */
  for (x = 0; x < (1 << winsize); x++) {
    if ((err = mp_init_size (&M[x], 1)) != MP_OKAY) {
      for (y = 0; y < x; y++) {
        mp_clear (&M[y]);
      }
      return err;
    }
  }

  /* create mu, used for Barrett reduction */
  if ((err = mp_init (&mu)) != MP_OKAY) {
    goto __M;
  }
  if ((err = mp_reduce_setup (&mu, P)) != MP_OKAY) {
    goto __MU;
  }

  /* create M table
   *
   * The M table contains powers of the input base, e.g. M[x] = G^x mod P
   *
   * The first half of the table is not computed though accept for M[0] and M[1]
   */
  if ((err = mp_mod (G, P, &M[1])) != MP_OKAY) {
    goto __MU;
  }

  /* compute the value at M[1<<(winsize-1)] by squaring M[1] (winsize-1) times */
  if ((err = mp_copy (&M[1], &M[1 << (winsize - 1)])) != MP_OKAY) {
    goto __MU;
  }

  for (x = 0; x < (winsize - 1); x++) {
    if ((err = mp_sqr (&M[1 << (winsize - 1)], &M[1 << (winsize - 1)])) != MP_OKAY) {
      goto __MU;
    }
    if ((err = mp_reduce (&M[1 << (winsize - 1)], P, &mu)) != MP_OKAY) {
      goto __MU;
    }
  }

  /* create upper table */
  for (x = (1 << (winsize - 1)) + 1; x < (1 << winsize); x++) {
    if ((err = mp_mul (&M[x - 1], &M[1], &M[x])) != MP_OKAY) {
      goto __MU;
    }
    if ((err = mp_reduce (&M[x], P, &mu)) != MP_OKAY) {
      goto __MU;
    }
  }

  /* setup result */
  if ((err = mp_init (&res)) != MP_OKAY) {
    goto __MU;
  }
  mp_set (&res, 1);

  /* set initial mode and bit cnt */
  mode   = 0;
  bitcnt = 1;
  buf    = 0;
  digidx = X->used - 1;
  bitcpy = bitbuf = 0;

  for (;;) {
    /* grab next digit as required */
    if (--bitcnt == 0) {
      if (digidx == -1) {
        break;
      }
      buf = X->dp[digidx--];
      bitcnt = (int) DIGIT_BIT;
    }

    /* grab the next msb from the exponent */
    y = (buf >> (mp_digit)(DIGIT_BIT - 1)) & 1;
    buf <<= (mp_digit)1;

    /* if the bit is zero and mode == 0 then we ignore it
     * These represent the leading zero bits before the first 1 bit
     * in the exponent.  Technically this opt is not required but it
     * does lower the # of trivial squaring/reductions used
     */
    if (mode == 0 && y == 0)
      continue;

    /* if the bit is zero and mode == 1 then we square */
    if (mode == 1 && y == 0) {
      if ((err = mp_sqr (&res, &res)) != MP_OKAY) {
        goto __RES;
      }
      if ((err = mp_reduce (&res, P, &mu)) != MP_OKAY) {
        goto __RES;
      }
      continue;
    }

    /* else we add it to the window */
    bitbuf |= (y << (winsize - ++bitcpy));
    mode = 2;

    if (bitcpy == winsize) {
      /* ok window is filled so square as required and multiply  */
      /* square first */
      for (x = 0; x < winsize; x++) {
        if ((err = mp_sqr (&res, &res)) != MP_OKAY) {
          goto __RES;
        }
        if ((err = mp_reduce (&res, P, &mu)) != MP_OKAY) {
          goto __RES;
        }
      }

      /* then multiply */
      if ((err = mp_mul (&res, &M[bitbuf], &res)) != MP_OKAY) {
        goto __MU;
      }
      if ((err = mp_reduce (&res, P, &mu)) != MP_OKAY) {
        goto __MU;
      }

      /* empty window and reset */
      bitcpy = bitbuf = 0;
      mode = 1;
    }
  }

  /* if bits remain then square/multiply */
  if (mode == 2 && bitcpy > 0) {
    /* square then multiply if the bit is set */
    for (x = 0; x < bitcpy; x++) {
      if ((err = mp_sqr (&res, &res)) != MP_OKAY) {
        goto __RES;
      }
      if ((err = mp_reduce (&res, P, &mu)) != MP_OKAY) {
        goto __RES;
      }

      bitbuf <<= 1;
      if ((bitbuf & (1 << winsize)) != 0) {
        /* then multiply */
        if ((err = mp_mul (&res, &M[1], &res)) != MP_OKAY) {
          goto __RES;
        }
        if ((err = mp_reduce (&res, P, &mu)) != MP_OKAY) {
          goto __RES;
        }
      }
    }
  }

  mp_exch (&res, Y);
  err = MP_OKAY;
__RES:mp_clear (&res);
__MU:mp_clear (&mu);
__M:
  for (x = 0; x < (1 << winsize); x++) {
    mp_clear (&M[x]);
  }
  return err;
}
