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
   "4",
   "F///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "//////m3wvV"
},
#endif
#ifdef DH1024
{
   128,
   "DH-1024",
   "4",
   "F///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////m3C47"
},
#endif
#ifdef DH1280
{
   160,
   "DH-1280",
   "4",
   "F///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "//////////////////////////////m4kSN"
},
#endif
#ifdef DH1536
{
   192,
   "DH-1536",
   "4",
   "F///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////m5uqd"
},
#endif
#ifdef DH1792
{
   224,
   "DH-1792",
   "4",
   "F///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "//////////////////////////////////////////////////////mT/sd"
},
#endif
#ifdef DH2048
{
   256,
   "DH-2048",
   "4",
   "3///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "/////////////////////////////////////////m8MPh"
},
#endif
#ifdef DH2560
{
   320,
   "DH-2560",
   "4",
   "3///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "/////mKFpF"
},
#endif
#ifdef DH3072
{
   384,
   "DH-3072",
   "4",
   "3///////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "/////////////////////////////m32nN"
},
#endif
#ifdef DH4096
{
   512,
   "DH-4096",
   "4",
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "////////////////////////////////////////////////////////////"
   "/////////////////////m8pOF"
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

    if ((res = mp_init_multi(&p, &g, &tmp, NULL)) != MP_OKAY)                 { goto error; }

    for (x = 0; sets[x].size != 0; x++) {
#if 0
        printf("dh_test():testing size %d-bits\n", sets[x].size * 8);
#endif
        if ((res = mp_read_radix(&g,(char *)sets[x].base, 64)) != MP_OKAY)    { goto error; }
        if ((res = mp_read_radix(&p,(char *)sets[x].prime, 64)) != MP_OKAY)   { goto error; }

        /* ensure p is prime */
        if ((res = is_prime(&p, &primality)) != CRYPT_OK)                     { goto done; }
        if (primality == 0) {
           res = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }

        if ((res = mp_sub_d(&p, 1, &tmp)) != MP_OKAY)                         { goto error; }
        if ((res = mp_div_2(&tmp, &tmp)) != MP_OKAY)                          { goto error; }

        /* ensure (p-1)/2 is prime */
        if ((res = is_prime(&tmp, &primality)) != CRYPT_OK)                   { goto done; }
        if (primality == 0) {
           res = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }

        /* now see if g^((p-1)/2) mod p is in fact 1 */
        if ((res = mp_exptmod(&g, &tmp, &p, &tmp)) != MP_OKAY)                { goto error; }
        if (mp_cmp_d(&tmp, 1)) {
           res = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }
    }
    res = CRYPT_OK;
    goto done;
error:
    res = mpi_to_ltc_error(res);
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
   if ((res = mp_init_multi(&g, &p, &key->x, &key->y, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(res);
   }
   if ((res = mp_read_radix(&g, sets[key->idx].base, 64)) != MP_OKAY)      { goto error; }
   if ((res = mp_read_radix(&p, sets[key->idx].prime, 64)) != MP_OKAY)     { goto error; }

   /* load the x value */
   if ((res = mp_read_unsigned_bin(&key->x, buf, keysize)) != MP_OKAY)     { goto error; }
   if ((res = mp_exptmod(&g, &key->x, &p, &key->y)) != MP_OKAY)            { goto error; }
   key->type = PK_PRIVATE;

   if ((res = mp_shrink(&key->x)) != MP_OKAY)                              { goto error; }
   if ((res = mp_shrink(&key->y)) != MP_OKAY)                              { goto error; }

   /* free up ram */
   res = CRYPT_OK;
   goto done2;
error:
   res = mpi_to_ltc_error(res);
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
      if ((err = mp_to_unsigned_bin(num, buf2+y)) != MP_OKAY) { return mpi_to_ltc_error(err); }   \
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
     if ((err = mp_read_unsigned_bin(num, (unsigned char *)in+y, (int)x)) != MP_OKAY) {\
        err = mpi_to_ltc_error(err);                                      \
        goto error;                                              \
     }                                                           \
     y += x;                                                     \
     if ((err = mp_shrink(num)) != MP_OKAY) {                            \
        err = mpi_to_ltc_error(err);                                       \
        goto error;                                              \
     }                                                           \
}


int dh_export(unsigned char *out, unsigned long *outlen, int type, dh_key *key)
{
   unsigned char buf2[1536];
   unsigned long y, z;
   int err;

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
   if ((err = mp_init_multi(&key->x, &key->y, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
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

   if (mp_read_radix(&p, (char *)sets[private_key->idx].prime, 64) != MP_OKAY)     { goto error; }
   if (mp_exptmod(&public_key->y, &private_key->x, &p, &tmp) != MP_OKAY)           { goto error; }

   /* enough space for output? */
   x = (unsigned long)mp_unsigned_bin_size(&tmp);
   if (*outlen < x) {
      res = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }
   if (mp_to_unsigned_bin(&tmp, out) != MP_OKAY)                                   { goto error; }
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

