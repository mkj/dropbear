#include "mycrypt.h"

#ifdef MDH

/* This holds the key settings.  ***MUST*** be organized by size from smallest to largest. */
static const struct {
    int size;
    char *name, *base, *prime;
} sets[] = {
#ifdef DH768
{
   96,
   "DH-768",
   "2",
   "1tH+dRFGpEYyVLe4ydZcYyGDpeAxnChz0yk+pNCtkEXwUsOORyguBtx8spUD"
   "FAjEDS8PutUBTEu2q4USqu19dUbCLj9D2jY7y3871RnSccurMBsMm35ILcyQ"
    "rpN0MQKc/"
},
#endif
#ifdef DH1024
{
   128,
   "DH-1024",
   "2",
   "Uypu+t9nfUnCj7xD+xokM+Cd6mASW4ofg1jpC2BpQasC5edtA1dJC+RjbOBZ"
   "z+5mvq5VYT8Wfjmlpjm9tQxHOYB0+3Myl7gbCQ5SRljWT2oBLukLNvgFjiU4"
   "wiWkmu41Ern/j6uxwKb740C+VIgDAdeUY4fA5hyfr3/+DWYb14/"
},
#endif
#ifdef DH1280
{
   160,
   "DH-1280",
   "2",
   "520QV4Tsq4NwK9Mt5CGR9xk4slvaikgi/ax3OPky5GERKTsoqEXOlFyMzURP"
   "P8jYzCVz1izKd2zTDxbFfLxrJry0ceaQ5YZa5N4teByCPVlQh4v6iQl+944+"
   "/NDlKzvWpx7HG7k8cGKhva7aFF8bP/CvLpaQhrfXlOX+X9pcmML9QH63tUjq"
   "B80l8Yx9KN0dC3iNnsTV3DnqnEvFQkoqql"
},
#endif
#ifdef DH1536
{
   192,
   "DH-1536",
   "3",
   "1FTWXrPcY1w74oZ0ouIzSN8uZcRiOf6U11fx0ka6+7fqIAezPhd3Ab43QnDf"
   "KFg+or/fFRGEWAxF8WIE2jx8iTOu010yNEQyH14CK0RAyy2zY4gRs2MpnU5r"
   "/feWf60OkLtnPzN34+Xnlg5xf7Jl00wkHRCeJG17L3SklOidAPxWnE+Wm4BS"
   "SOzdQBgiZOjlhrYS1+TIU3NP5H7BrtKFcf+ZwBULibf29L7LkDOgQbie1+43"
   "lU+8SHAyBwAeGYMfZ"
},
#endif
#ifdef DH1792
{
   224,
   "DH-1792",
   "2",
   "IPo3wjvfS7vBYnFHwJHmesA51od9fnR8Aenezif4qLE2HX+YCv1tpvHA8yLH"
   "yYbKe9QfSHHtOgVjK8AYEyPirpXxlmdykGuj+dX7EiWMRGYc+v1kKkqmCn0o"
   "5tU416O/1HXTpQ2Hps0buchUD+HlCMrSgnIqRxK6Fjr0ZfiCS4XgAD6sLgi0"
   "BxKFMxDsVzpGMNwF5Lj2R/cJiTi0cNDDY3gn4lK/PRUsJtRKU+9sxy0q5Yof"
   "aG5VO8VcHkZJVwUKhDFHkZYWMHV808TGHXM2RQ9kRa2QvS2mXxMrDSCloQ/"
},
#endif
#ifdef DH2048
{
   256,
   "DH-2048",
   "2",
   "5sR1VmdsQQzzjN0iridVVyveug6sAC3+/jTIHSgEoimPOREXQ05r2WJZJAF2"
   "CRu8kuusiPw2ivRli+fdLr63v1uZG5nQa28uLwNxZEsu4gu6TrGjepXeXm4Z"
   "CVOC1HMmi660fLZ2ruHLa4v2NWex2Zx91/y4ygPlZM+K//iy+Gft9Ma9Ayn0"
   "eYwofZeUL9vJSfutPVp2ZrIEUQDBKMvMm0SRSLiUjDtzXqrH+b/wuwIFG1K4"
   "var3ucsT45mDzD9qb3tBdksSPZbr6yrELV8h+qmjiBr15oHKEglS0XwSvCap"
   "abUn5XPPVoaKv13+tOnG9mGgzQ8JeClVXN63Q+GGEF"
},
#endif
#ifdef DH2560
{
   320,
   "DH-2560",
   "3",
   "G7UVKk+N6LfpGkdBP6XLB4QJ3wzee5YH/3o6tBDMwr4FS8YjCmeP6l4gu0hX"
   "dzY2Rive4TYOu4Akm4naZuv32d71/2lQeNcO23BNYOEPxtn9BU8uYfaHP9Mo"
   "M+m76oUCiI5uqpag5RH3BO34FyE4BiKkzjEXq9xxc8ERacG8Mo8DNiXu79p9"
   "Q/0wsRz+W/lIN4gYw3w4iLMooAGnDrhcj5cZb0HysHWYfqmFo+jTBP6Egi0g"
   "cmVO2qWQh2cZIQMfppaf1Ffq0XGIJpgDFyOHPl3NVxDabVK1tkVct+hathxJ"
   "UTdqZmR2VFwMASXjfgj4VFdvFCUxV8Xr8JcwXkwlMjOJbAl0LoCa4M7hpYvz"
   "G/0XviGCpv7qQaONKtsiQ6mHhMcyo9hBCRZXtNPkfPMZkPeV05akvaDs6Ek7"
   "DZ62oKR"
},
#endif
#ifdef DH3072
{
   384,
   "DH-3072",
   "2",
   "1zsV6XgY57R/hu2RR4H/BjwRqmQL9h+Dc5rgoWOcqiTS8qpVTWafi1KFV77V"
   "rUcjcer1EDgCV0tpzlemtyrC2pHpw7hr3EEl2evfWOvg05FRI6mKc2UPNv2c"
   "2Bjww4LD/tdsLleX7AHHXCXFSSyd6C3qWq7BqABZriSpQeaEtXbWfeC6ytFe"
   "2i3VeQsLa40XQ21UxwhPAjamjSOfYzkW7xi0fwI1e+4OQiFcWOfOuvswoaEf"
   "MIICyAmVp67vjGo66dk81dMemyplipgXAWPdl7ppnDd6cEjyN4N90D7kQiNg"
   "lVmJlKLecldOUtdIqMnbJCbiN/t/3/AEFaokGO9om5ckc6M9gG5PG0T7Oh1N"
   "dSx/PstGdxwvs9DOwjyo5wl5C9QSLtUYJl2+GZYMj6WfsgCrb6jjRJJJQe2C"
   "y7wUcBILbRsP3lYT8s14zm4xFBrfMUoLN287j3wQ1TNUXjYSCi4ZLKT1XDai"
   "93345OiutLOqGGikFg6ypnymJK3yeHuul"
},
#endif
#ifdef DH4096
{
   512,
   "DH-4096",
   "3",
   "Id8ukxZdao3hS0NGTKAXdt3c8PpiyigIyBY8lwOHjM2cqkaZgwvr1pA6OowS"
   "32kJkeOqKB8gNTZZZVqOFkPXgvC4WveUgA5a7rhTj28pDidNROmMO70CCcSw"
   "aHI3GLFuEMz3JJyvQKGaGwpV3C9gS70dFWTxEfNRzdYEdvIic8/SXI79VgNP"
   "LGR68nzd4qxCgaLpVBnWsanRp7mfEj52S/7Kxjs14lrbAOMjCuHgN4F6THWh"
   "PNhG0VXfFFIwAMW2unrfpdo+gQHNclqCf2N1FALpABzvUesgs3wIP+QTMqms"
   "os/AkuulG7MusbeFl3SoCtaoW12CF038ZbqW+e+DKI1zObhtsLanvaiZm/N4"
   "BsJirW7avcWNQYm1oYjZ2bR/jYqfoJ0CLXLO/vqHb8J9a5VE9nz7cqMD3/MH"
   "k/g7BapsOtKuol6ipbUvxQPtf4KCwqQQ40JeqgS6amivI/aLu05S7bAxKOwE"
   "Yu8YxjN6lXm3co5Wy+BmNSuRlzKhxICyHEqMfKwUtm48XHzHuPaGQzHgkn6H"
   "3A+FQjQGLHewADYlbfdTF3sHYyc5k9h/9cYVkbmv7bQze53CJGr3T1hZYbN6"
   "+fuz0SPnfjiKu+bWD+8RYtZpLs2+f32huMz3OqoryGfULxC2aEjL2rdBn+ZR"
   "PT0+ZAUyLSAVHbsul++cawh"
},
#endif
{
   0,
   NULL,
   NULL,
   NULL
}
};

static int is_valid_idx(int n)
{
   int x;

   for (x = 0; sets[x].size; x++);
   if ((n < 0) || (n >= x)) {
      return 0;
   }
   return 1;
}

int dh_test(void)
{
    mp_int p, g, tmp;
    int x, res, primality;

    if (mp_init_multi(&p, &g, &tmp, NULL) != MP_OKAY)                 { goto error; }

    for (x = 0; sets[x].size != 0; x++) {
#if 0
        printf("dh_test():testing size %d-bits\n", sets[x].size * 8);
#endif
        if (mp_read_radix(&g,(unsigned char *)sets[x].base, 64) != MP_OKAY)   { goto error; }
        if (mp_read_radix(&p,(unsigned char *)sets[x].prime, 64) != MP_OKAY)  { goto error; }

        /* ensure p is prime */
        if ((res = is_prime(&p, &primality)) != CRYPT_OK)             { goto done; }
        if (primality == 0) {
           res = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }

        if (mp_sub_d(&p, 1, &tmp) != MP_OKAY)                         { goto error; }
        if (mp_div_2(&tmp, &tmp) != MP_OKAY)                          { goto error; }

        /* ensure (p-1)/2 is prime */
        if ((res = is_prime(&tmp, &primality)) != CRYPT_OK)           { goto done; }
        if (primality == 0) {
           res = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }

        /* now see if g^((p-1)/2) mod p is in fact 1 */
        if (mp_exptmod(&g, &tmp, &p, &tmp) != MP_OKAY)                { goto error; }
        if (mp_cmp_d(&tmp, 1)) {
           res = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }
    }
    res = CRYPT_OK;
    goto done;
error:
    res = CRYPT_MEM;
done:
    mp_clear_multi(&tmp, &g, &p, NULL);
    return res;
}

void dh_sizes(int *low, int *high)
{
   int x;
   _ARGCHK(low != NULL);
   _ARGCHK(high != NULL);
   *low  = INT_MAX;
   *high = 0;
   for (x = 0; sets[x].size != 0; x++) {
       if (*low > sets[x].size)  *low  = sets[x].size;
       if (*high < sets[x].size) *high = sets[x].size;
   }
}

int dh_get_size(dh_key *key)
{
    _ARGCHK(key != NULL);
    if (is_valid_idx(key->idx) == 1) {
        return sets[key->idx].size;
    } else {
        return INT_MAX; /* large value that would cause dh_make_key() to fail */
    }
}

int dh_make_key(prng_state *prng, int wprng, int keysize, dh_key *key)
{
   unsigned char buf[512];
   unsigned long x;
   mp_int p, g;
   int res, err;

   _ARGCHK(key  != NULL);

   /* good prng? */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* find key size */
   for (x = 0; (keysize > sets[x].size) && (sets[x].size != 0); x++);
#ifdef FAST_PK
   keysize = MIN(sets[x].size, 32);
#else
   keysize = sets[x].size;
#endif

   if (sets[x].size == 0) {
      return CRYPT_INVALID_KEYSIZE;
   }
   key->idx = x;

   /* make up random string */
   if (prng_descriptor[wprng].read(buf, keysize, prng) != (unsigned long)keysize) {
      return CRYPT_ERROR_READPRNG;
   }

   /* init parameters */
   if (mp_init_multi(&g, &p, &key->x, &key->y, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }
   if (mp_read_radix(&g, sets[key->idx].base, 64) != MP_OKAY)      { goto error; }
   if (mp_read_radix(&p, sets[key->idx].prime, 64) != MP_OKAY)     { goto error; }

   /* load the x value */
   if (mp_read_unsigned_bin(&key->x, buf, keysize) != MP_OKAY)     { goto error; }
   if (mp_exptmod(&g, &key->x, &p, &key->y) != MP_OKAY)            { goto error; }
   key->type = PK_PRIVATE;

   if (mp_shrink(&key->x) != MP_OKAY)                              { goto error; }
   if (mp_shrink(&key->y) != MP_OKAY)                              { goto error; }

   /* free up ram */
   res = CRYPT_OK;
   goto done2;
error:
   res = CRYPT_MEM;
   mp_clear_multi(&key->x, &key->y, NULL);
done2:
   mp_clear_multi(&p, &g, NULL);
   zeromem(buf, sizeof(buf));
   return res;
}

void dh_free(dh_key *key)
{
   _ARGCHK(key != NULL);
   mp_clear_multi(&key->x, &key->y, NULL);
}

#define OUTPUT_BIGNUM(num, buf2, y, z)         \
{                                              \
      z = (unsigned long)mp_unsigned_bin_size(num);           \
      STORE32L(z, buf2+y);                     \
      y += 4;                                  \
      (void)mp_to_unsigned_bin(num, buf2+y);   \
      y += z;                                  \
}


#define INPUT_BIGNUM(num, in, x, y)                              \
{                                                                \
     /* load value */                                            \
     if (y + 4 > inlen) {                                        \
        err = CRYPT_INVALID_PACKET;                            \
        goto error;                                              \
     }                                                           \
     LOAD32L(x, in+y);                                           \
     y += 4;                                                     \
                                                                 \
     /* sanity check... */                                       \
     if (x+y > inlen) {                                          \
        err = CRYPT_INVALID_PACKET;                            \
        goto error;                                              \
     }                                                           \
                                                                 \
     /* load it */                                               \
     if (mp_read_unsigned_bin(num, (unsigned char *)in+y, (int)x) != MP_OKAY) {\
        err =  CRYPT_MEM;                                      \
        goto error;                                              \
     }                                                           \
     y += x;                                                     \
     if (mp_shrink(num) != MP_OKAY) {                            \
        err = CRYPT_MEM;                                       \
        goto error;                                              \
     }                                                           \
}


int dh_export(unsigned char *out, unsigned long *outlen, int type, dh_key *key)
{
   unsigned char buf2[1536];
   unsigned long y, z;

   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);

   if (type == PK_PRIVATE && key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* header */
   y = PACKET_SIZE;

   /* header */
   buf2[y++] = type;
   buf2[y++] = (unsigned char)(sets[key->idx].size / 8);

   /* export y */
   OUTPUT_BIGNUM(&key->y, buf2, y, z);

   if (type == PK_PRIVATE) {
      /* export x */
      OUTPUT_BIGNUM(&key->x, buf2, y, z);
   }

   /* check for overflow */
   if (*outlen < y) {
      #ifdef CLEAN_STACK
         zeromem(buf2, sizeof(buf2));
      #endif
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* store header */
   packet_store_header(buf2, PACKET_SECT_DH, PACKET_SUB_KEY);

   /* output it */
   *outlen = y;
   memcpy(out, buf2, (size_t)y);

   /* clear mem */
#ifdef CLEAN_STACK
   zeromem(buf2, sizeof(buf2));
#endif
   return CRYPT_OK;
}

int dh_import(const unsigned char *in, unsigned long inlen, dh_key *key)
{
   unsigned long x, y, s;
   int err;

   _ARGCHK(in != NULL);
   _ARGCHK(key != NULL);

   /* make sure valid length */
   if (2+PACKET_SIZE > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   /* check type byte */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_DH, PACKET_SUB_KEY)) != CRYPT_OK) {
      return err;
   }

   /* init */
   if (mp_init_multi(&key->x, &key->y, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }

   /* advance past packet header */
   y = PACKET_SIZE;

   /* key type, e.g. private, public */
   key->type = (int)in[y++];

   /* key size in bytes */
   s  = (unsigned long)in[y++] * 8;

   for (x = 0; (s > (unsigned long)sets[x].size) && (sets[x].size != 0); x++);
   if (sets[x].size == 0) {
      err = CRYPT_INVALID_KEYSIZE;
      goto error;
   }
   key->idx = (int)x;

   /* type check both values */
   if ((key->type != PK_PUBLIC) && (key->type != PK_PRIVATE))  {
      err = CRYPT_PK_TYPE_MISMATCH;
      goto error;
   }

   /* is the key idx valid? */
   if (is_valid_idx(key->idx) != 1) {
      err = CRYPT_PK_TYPE_MISMATCH;
      goto error;
   }

   /* load public value g^x mod p*/
   INPUT_BIGNUM(&key->y, in, x, y);

   if (key->type == PK_PRIVATE) {
      INPUT_BIGNUM(&key->x, in, x, y);
   }

   /* eliminate private key if public */
   if (key->type == PK_PUBLIC) {
      mp_clear(&key->x);
   }

   return CRYPT_OK;
error:
   mp_clear_multi(&key->y, &key->x, NULL);
   return err;
}

int dh_shared_secret(dh_key *private_key, dh_key *public_key,
                     unsigned char *out, unsigned long *outlen)
{
   mp_int tmp, p;
   unsigned long x;
   int res;

   _ARGCHK(private_key != NULL);
   _ARGCHK(public_key  != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* types valid? */
   if (private_key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* same idx? */
   if (private_key->idx != public_key->idx) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   /* compute y^x mod p */
   if (mp_init_multi(&tmp, &p, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }

   if (mp_read_radix(&p, (unsigned char *)sets[private_key->idx].prime, 64) != MP_OKAY)     { goto error; }
   if (mp_exptmod(&public_key->y, &private_key->x, &p, &tmp) != MP_OKAY)                    { goto error; }

   /* enough space for output? */
   x = (unsigned long)mp_unsigned_bin_size(&tmp);
   if (*outlen < x) {
      res = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }
   if (mp_to_unsigned_bin(&tmp, out) != MP_OKAY)                                            { goto error; }
   *outlen = x;
   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
done:
   mp_clear_multi(&p, &tmp, NULL);
   return res;
}

#include "dh_sys.c"

#endif

