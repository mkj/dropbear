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

/* chars used in radix conversions */
static const char *s_rmap = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

/* read a string [ASCII] in a given radix */
int
mp_read_radix (mp_int * a, char *str, int radix)
{
  int     y, res, neg;
  char    ch;

  if (radix < 2 || radix > 64) {
    return MP_VAL;
  }

  if (*str == '-') {
    ++str;
    neg = MP_NEG;
  } else {
    neg = MP_ZPOS;
  }

  mp_zero (a);
  while (*str) {
    ch = (char) ((radix < 36) ? toupper (*str) : *str);
    for (y = 0; y < 64; y++) {
      if (ch == s_rmap[y]) {
    break;
      }
    }

    if (y < radix) {
      if ((res = mp_mul_d (a, (mp_digit) radix, a)) != MP_OKAY) {
    return res;
      }
      if ((res = mp_add_d (a, (mp_digit) y, a)) != MP_OKAY) {
    return res;
      }
    } else {
      break;
    }
    ++str;
  }
  if (mp_iszero(a) != 1) {
     a->sign = neg;
  }
  return MP_OKAY;
}

/* stores a bignum as a ASCII string in a given radix (2..64) */
int
mp_toradix (mp_int * a, char *str, int radix)
{
  int     res, digs;
  mp_int  t;
  mp_digit d;
  char   *_s = str;

  if (radix < 2 || radix > 64) {
    return MP_VAL;
  }
  
  /* quick out if its zero */
  if (mp_iszero(a) == 1) {
     *str++ = '0';
     *str = '\0';
     return MP_OKAY;
  }
  

  if ((res = mp_init_copy (&t, a)) != MP_OKAY) {
    return res;
  }

  if (t.sign == MP_NEG) {
    ++_s;
    *str++ = '-';
    t.sign = MP_ZPOS;
  }

  digs = 0;
  while (mp_iszero (&t) == 0) {
    if ((res = mp_div_d (&t, (mp_digit) radix, &t, &d)) != MP_OKAY) {
      mp_clear (&t);
      return res;
    }
    *str++ = s_rmap[d];
    ++digs;
  }
  bn_reverse ((unsigned char *)_s, digs);
  *str++ = '\0';
  mp_clear (&t);
  return MP_OKAY;
}

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

/* read a bigint from a file stream in ASCII */
int mp_fread(mp_int *a, int radix, FILE *stream)
{
   int err, ch, neg, y;
   
   /* clear a */
   mp_zero(a);
   
   /* if first digit is - then set negative */
   ch = fgetc(stream);
   if (ch == '-') {
      neg = MP_NEG;
      ch = fgetc(stream);
   } else {
      neg = MP_ZPOS;
   }
   
   for (;;) {
      /* find y in the radix map */
      for (y = 0; y < radix; y++) {
          if (s_rmap[y] == ch) {
             break;
          }
      }
      if (y == radix) {
         break;
      }
      
      /* shift up and add */
      if ((err = mp_mul_d(a, radix, a)) != MP_OKAY) {
         return err;
      }
      if ((err = mp_add_d(a, y, a)) != MP_OKAY) {
         return err;
      }
      
      ch = fgetc(stream);
   }
   if (mp_cmp_d(a, 0) != MP_EQ) {
      a->sign = neg;
   }
   
   return MP_OKAY;
}

int mp_fwrite(mp_int *a, int radix, FILE *stream)
{
   char *buf;
   int err, len, x;
   
   len = mp_radix_size(a, radix);
   if (len == 0) {
      return MP_VAL;
   }
   
   buf = malloc(len);
   if (buf == NULL) {
      return MP_MEM;
   }
   
   if ((err = mp_toradix(a, buf, radix)) != MP_OKAY) {
      free(buf);
      return err;
   }
   
   for (x = 0; x < len; x++) {
       if (fputc(buf[x], stream) == EOF) {
          free(buf);
          return MP_VAL;
       }
   }
   
   free(buf);
   return MP_OKAY;
}

