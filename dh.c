/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://libtomcrypt.org
 */
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
    int x, err, primality;

    if ((err = mp_init_multi(&p, &g, &tmp, NULL)) != MP_OKAY)                 { goto error; }

    for (x = 0; sets[x].size != 0; x++) {
#if 0
        printf("dh_test():testing size %d-bits\n", sets[x].size * 8);
#endif
        if ((err = mp_read_radix(&g,(char *)sets[x].base, 64)) != MP_OKAY)    { goto error; }
        if ((err = mp_read_radix(&p,(char *)sets[x].prime, 64)) != MP_OKAY)   { goto error; }

        /* ensure p is prime */
        if ((err = is_prime(&p, &primality)) != CRYPT_OK)                     { goto done; }
        if (primality == 0) {
           err = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }

        if ((err = mp_sub_d(&p, 1, &tmp)) != MP_OKAY)                         { goto error; }
        if ((err = mp_div_2(&tmp, &tmp)) != MP_OKAY)                          { goto error; }

        /* ensure (p-1)/2 is prime */
        if ((err = is_prime(&tmp, &primality)) != CRYPT_OK)                   { goto done; }
        if (primality == 0) {
           err = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }

        /* now see if g^((p-1)/2) mod p is in fact 1 */
        if ((err = mp_exptmod(&g, &tmp, &p, &tmp)) != MP_OKAY)                { goto error; }
        if (mp_cmp_d(&tmp, 1)) {
           err = CRYPT_FAIL_TESTVECTOR;
           goto done;
        }
    }
    err = CRYPT_OK;
    goto done;
error:
    err = mpi_to_ltc_error(err);
done:
    mp_clear_multi(&tmp, &g, &p, NULL);
    return err;
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
   int err;

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
   if ((err = mp_init_multi(&g, &p, &key->x, &key->y, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }
   if ((err = mp_read_radix(&g, sets[key->idx].base, 64)) != MP_OKAY)      { goto error; }
   if ((err = mp_read_radix(&p, sets[key->idx].prime, 64)) != MP_OKAY)     { goto error; }

   /* load the x value */
   if ((err = mp_read_unsigned_bin(&key->x, buf, keysize)) != MP_OKAY)     { goto error; }
   if ((err = mp_exptmod(&g, &key->x, &p, &key->y)) != MP_OKAY)            { goto error; }
   key->type = PK_PRIVATE;

   if ((err = mp_shrink(&key->x)) != MP_OKAY)                              { goto error; }
   if ((err = mp_shrink(&key->y)) != MP_OKAY)                              { goto error; }

   /* free up ram */
   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
   mp_clear_multi(&key->x, &key->y, NULL);
done:
   mp_clear_multi(&p, &g, NULL);
   zeromem(buf, sizeof(buf));
   return err;
}

void dh_free(dh_key *key)
{
   _ARGCHK(key != NULL);
   mp_clear_multi(&key->x, &key->y, NULL);
}

int dh_export(unsigned char *out, unsigned long *outlen, int type, dh_key *key)
{
   unsigned long y, z;
   int err;

   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key    != NULL);

   /* can we store the static header?  */
   if (*outlen < (PACKET_SIZE + 2)) {
      return CRYPT_BUFFER_OVERFLOW;
   }
   
   if (type == PK_PRIVATE && key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* header */
   y = PACKET_SIZE;

   /* header */
   out[y++] = type;
   out[y++] = (unsigned char)(sets[key->idx].size / 8);

   /* export y */
   OUTPUT_BIGNUM(&key->y, out, y, z);

   if (type == PK_PRIVATE) {
      /* export x */
      OUTPUT_BIGNUM(&key->x, out, y, z);
   }

   /* store header */
   packet_store_header(out, PACKET_SECT_DH, PACKET_SUB_KEY);

   /* store len */
   *outlen = y;
   return CRYPT_OK;
}

int dh_import(const unsigned char *in, unsigned long inlen, dh_key *key)
{
   unsigned long x, y, s;
   int err;

   _ARGCHK(in  != NULL);
   _ARGCHK(key != NULL);

   /* make sure valid length */
   if ((2+PACKET_SIZE) > inlen) {
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
   INPUT_BIGNUM(&key->y, in, x, y, inlen);

   if (key->type == PK_PRIVATE) {
      INPUT_BIGNUM(&key->x, in, x, y, inlen);
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
   int err;

   _ARGCHK(private_key != NULL);
   _ARGCHK(public_key  != NULL);
   _ARGCHK(out         != NULL);
   _ARGCHK(outlen      != NULL);

   /* types valid? */
   if (private_key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* same idx? */
   if (private_key->idx != public_key->idx) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   /* compute y^x mod p */
   if ((err = mp_init_multi(&tmp, &p, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   if ((err = mp_read_radix(&p, (char *)sets[private_key->idx].prime, 64)) != MP_OKAY)     { goto error; }
   if ((err = mp_exptmod(&public_key->y, &private_key->x, &p, &tmp)) != MP_OKAY)           { goto error; }

   /* enough space for output? */
   x = (unsigned long)mp_unsigned_bin_size(&tmp);
   if (*outlen < x) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }
   if ((err = mp_to_unsigned_bin(&tmp, out)) != MP_OKAY)                                   { goto error; }
   *outlen = x;
   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&p, &tmp, NULL);
   return err;
}

#include "dh_sys.c"

#endif

