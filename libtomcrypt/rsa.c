/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * gurantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://libtomcrypt.org
 */

/* RSA Code by Tom St Denis */
#include "mycrypt.h"

/* Min and Max RSA key sizes (in bits) */
#define MIN_RSA_SIZE 1024
#define MAX_RSA_SIZE 4096

/* Stack required for temps (plus padding) */
#define RSA_STACK    (8 + (MAX_RSA_SIZE/8))

#ifdef MRSA

int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key)
{
   mp_int p, q, tmp1, tmp2, tmp3;
   int err;

   _ARGCHK(key != NULL);

   if ((size < (MIN_RSA_SIZE/8)) || (size > (MAX_RSA_SIZE/8))) {
      return CRYPT_INVALID_KEYSIZE;
   }

   if ((e < 3) || ((e & 1) == 0)) {
      return CRYPT_INVALID_ARG;
   }

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   if ((err = mp_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* make primes p and q (optimization provided by Wayne Scott) */
   if ((err = mp_set_int(&tmp3, e)) != MP_OKAY) { goto error; }            /* tmp3 = e */

   /* make prime "p" */
   do {
       if ((err = rand_prime(&p, size/2, prng, wprng)) != CRYPT_OK) { goto done; }
       if ((err = mp_sub_d(&p, 1, &tmp1)) != MP_OKAY)               { goto error; }  /* tmp1 = p-1 */
       if ((err = mp_gcd(&tmp1, &tmp3, &tmp2)) != MP_OKAY)          { goto error; }  /* tmp2 = gcd(p-1, e) */
   } while (mp_cmp_d(&tmp2, 1) != 0);                                                /* while e divides p-1 */

   /* make prime "q" */
   do {
       if ((err = rand_prime(&q, size/2, prng, wprng)) != CRYPT_OK) { goto done; }
       if ((err = mp_sub_d(&q, 1, &tmp1)) != MP_OKAY)               { goto error; } /* tmp1 = q-1 */
       if ((err = mp_gcd(&tmp1, &tmp3, &tmp2)) != MP_OKAY)          { goto error; } /* tmp2 = gcd(q-1, e) */
   } while (mp_cmp_d(&tmp2, 1) != 0);                                               /* while e divides q-1 */

   /* tmp1 = lcm(p-1, q-1) */
   if ((err = mp_sub_d(&p, 1, &tmp2)) != MP_OKAY)                  { goto error; } /* tmp2 = p-1 */
                                                                   /* tmp1 = q-1 (previous do/while loop) */
   if ((err = mp_lcm(&tmp1, &tmp2, &tmp1)) != MP_OKAY)             { goto error; } /* tmp1 = lcm(p-1, q-1) */

   /* make key */
   if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP,
                     &key->qP, &key->pQ, &key->p, &key->q, NULL)) != MP_OKAY) {
      goto error;
   }

   if ((err = mp_set_int(&key->e, e)) != MP_OKAY)                  { goto error2; } /* key->e =  e */
   if ((err = mp_invmod(&key->e, &tmp1, &key->d)) != MP_OKAY)      { goto error2; } /* key->d = 1/e mod lcm(p-1,q-1) */
   if ((err = mp_mul(&p, &q, &key->N)) != MP_OKAY)                 { goto error2; } /* key->N = pq */

/* optimize for CRT now */
   /* find d mod q-1 and d mod p-1 */
   if ((err = mp_sub_d(&p, 1, &tmp1)) != MP_OKAY)                  { goto error2; } /* tmp1 = q-1 */
   if ((err = mp_sub_d(&q, 1, &tmp2)) != MP_OKAY)                  { goto error2; } /* tmp2 = p-1 */

   if ((err = mp_mod(&key->d, &tmp1, &key->dP)) != MP_OKAY)        { goto error2; } /* dP = d mod p-1 */
   if ((err = mp_mod(&key->d, &tmp2, &key->dQ)) != MP_OKAY)        { goto error2; } /* dQ = d mod q-1 */

   if ((err = mp_invmod(&q, &p, &key->qP)) != MP_OKAY)             { goto error2; } /* qP = 1/q mod p */
   if ((err = mp_mulmod(&key->qP, &q, &key->N, &key->qP)) != MP_OKAY)         { goto error2; } /* qP = q * (1/q mod p) mod N */

   if ((err = mp_invmod(&p, &q, &key->pQ)) != MP_OKAY)             { goto error2; } /* pQ = 1/p mod q */
   if ((err = mp_mulmod(&key->pQ, &p, &key->N, &key->pQ)) != MP_OKAY)         { goto error2; } /* pQ = p * (1/p mod q) mod N */

   if ((err = mp_copy(&p, &key->p)) != MP_OKAY)                    { goto error2; }
   if ((err = mp_copy(&q, &key->q)) != MP_OKAY)                    { goto error2; }

   /* shrink ram required  */
   if ((err = mp_shrink(&key->e)) != MP_OKAY)                      { goto error2; }
   if ((err = mp_shrink(&key->d)) != MP_OKAY)                      { goto error2; }
   if ((err = mp_shrink(&key->N)) != MP_OKAY)                      { goto error2; }
   if ((err = mp_shrink(&key->dQ)) != MP_OKAY)                     { goto error2; }
   if ((err = mp_shrink(&key->dP)) != MP_OKAY)                     { goto error2; }
   if ((err = mp_shrink(&key->qP)) != MP_OKAY)                     { goto error2; }
   if ((err = mp_shrink(&key->pQ)) != MP_OKAY)                     { goto error2; }
   if ((err = mp_shrink(&key->p)) != MP_OKAY)                      { goto error2; }
   if ((err = mp_shrink(&key->q)) != MP_OKAY)                      { goto error2; }

   err = CRYPT_OK;
   key->type = PK_PRIVATE_OPTIMIZED;
   goto done;
error2:
   mp_clear_multi(&key->d, &key->e, &key->N, &key->dQ, &key->dP,
                  &key->qP, &key->pQ, &key->p, &key->q, NULL);
error:
   err = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&tmp3, &tmp2, &tmp1, &p, &q, NULL);
   return err;
}

void rsa_free(rsa_key *key)
{
   _ARGCHK(key != NULL);
   mp_clear_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP,
                  &key->qP, &key->pQ, &key->p, &key->q, NULL);
}

int rsa_exptmod(const unsigned char *in,  unsigned long inlen,
                      unsigned char *out, unsigned long *outlen, int which,
                      rsa_key *key)
{
   mp_int tmp, tmpa, tmpb;
   unsigned long x;
   int err;

   _ARGCHK(in     != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key    != NULL);

   if (which == PK_PRIVATE && (key->type != PK_PRIVATE && key->type != PK_PRIVATE_OPTIMIZED)) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* must be a private or public operation */
   if (which != PK_PRIVATE && which != PK_PUBLIC) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* init and copy into tmp */
   if ((err = mp_init_multi(&tmp, &tmpa, &tmpb, NULL)) != MP_OKAY)                     { goto error; }
   if ((err = mp_read_unsigned_bin(&tmp, (unsigned char *)in, (int)inlen)) != MP_OKAY) { goto error; }

   /* sanity check on the input */
   if (mp_cmp(&key->N, &tmp) == MP_LT) {
      err = CRYPT_PK_INVALID_SIZE;
      goto done;
   }

   /* are we using the private exponent and is the key optimized? */
   if (which == PK_PRIVATE && key->type == PK_PRIVATE_OPTIMIZED) {
      /* tmpa = tmp^dP mod p */
      if ((err = mp_exptmod(&tmp, &key->dP, &key->p, &tmpa)) != MP_OKAY)    { goto error; }

      /* tmpb = tmp^dQ mod q */
      if ((err = mp_exptmod(&tmp, &key->dQ, &key->q, &tmpb)) != MP_OKAY)    { goto error; }

      /* tmp = tmpa*qP + tmpb*pQ mod N */
      if ((err = mp_mul(&tmpa, &key->qP, &tmpa)) != MP_OKAY)                { goto error; }
      if ((err = mp_mul(&tmpb, &key->pQ, &tmpb)) != MP_OKAY)                { goto error; }
      if ((err = mp_addmod(&tmpa, &tmpb, &key->N, &tmp)) != MP_OKAY)        { goto error; }
   } else {
      /* exptmod it */
      if ((err = mp_exptmod(&tmp, which==PK_PRIVATE?&key->d:&key->e, &key->N, &tmp)) != MP_OKAY) { goto error; }
   }

   /* read it back */
   x = (unsigned long)mp_unsigned_bin_size(&tmp);
   if (x > *outlen) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }
   *outlen = x;

   /* convert it */
   if ((err = mp_to_unsigned_bin(&tmp, out)) != MP_OKAY)                    { goto error; }

   /* clean up and return */
   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&tmp, &tmpa, &tmpb, NULL);
   return err;
}

int rsa_signpad(const unsigned char *in,  unsigned long inlen,
                      unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y;

   _ARGCHK(in     != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

   if (*outlen < (3 * inlen)) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* check inlen */
   if (inlen > 512) {
      return CRYPT_PK_INVALID_SIZE;
   }

   for (y = x = 0; x < inlen; x++)
       out[y++] = (unsigned char)0xFF;
   for (x = 0; x < inlen; x++)
       out[y++] = in[x];
   for (x = 0; x < inlen; x++)
       out[y++] = (unsigned char)0xFF;
   *outlen = 3 * inlen;
   return CRYPT_OK;
}

int rsa_pad(const unsigned char *in,  unsigned long inlen,
                  unsigned char *out, unsigned long *outlen,
                  int wprng, prng_state *prng)
{
   unsigned char buf[3*(MAX_RSA_SIZE/8)];
   unsigned long x;
   int err;

   _ARGCHK(in     != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

   /* is output big enough? */
   if (*outlen < (3 * inlen)) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* get random padding required */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* check inlen */
   if (inlen > (MAX_RSA_SIZE/8)) {
      return CRYPT_PK_INVALID_SIZE;
   }

   if (prng_descriptor[wprng].read(buf, inlen*2-2, prng) != (inlen*2 - 2))  {
       return CRYPT_ERROR_READPRNG;
   }

   /* pad it like a sandwhich
    *
    * Looks like 0xFF R1 M R2 0xFF
    *
    * Where R1/R2 are random and exactly equal to the length of M minus one byte.
    */
   for (x = 0; x < inlen-1; x++) {
       out[x+1] = buf[x];
   }

   for (x = 0; x < inlen; x++) {
       out[x+inlen] = in[x];
   }

   for (x = 0; x < inlen-1; x++) {
       out[x+inlen+inlen] = buf[x+inlen-1];
   }

   /* last and first bytes are 0xFF */
   out[0] = out[inlen+inlen+inlen-1] = (unsigned char)0xFF;

   /* clear up and return */
#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   *outlen = inlen*3;
   return CRYPT_OK;
}

int rsa_signdepad(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen)
{
   unsigned long x;

   _ARGCHK(in     != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

   if (*outlen < inlen/3) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* check padding bytes */
   for (x = 0; x < inlen/3; x++) {
       if (in[x] != (unsigned char)0xFF || in[x+(inlen/3)+(inlen/3)] != (unsigned char)0xFF) {
          return CRYPT_INVALID_PACKET;
       }
   }
   for (x = 0; x < inlen/3; x++) {
       out[x] = in[x+(inlen/3)];
   }
   *outlen = inlen/3;
   return CRYPT_OK;
}

int rsa_depad(const unsigned char *in,  unsigned long inlen,
                    unsigned char *out, unsigned long *outlen)
{
   unsigned long x;

   _ARGCHK(in     != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

   if (*outlen < inlen/3) {
      return CRYPT_BUFFER_OVERFLOW;
   }
   for (x = 0; x < inlen/3; x++) {
       out[x] = in[x+(inlen/3)];
   }
   *outlen = inlen/3;
   return CRYPT_OK;
}

int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key)
{
   unsigned long y, z; 
   int err;

   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key    != NULL);
   
   /* can we store the static header?  */
   if (*outlen < (PACKET_SIZE + 1)) {
      return CRYPT_BUFFER_OVERFLOW;
   }   

   /* type valid? */
   if (!(key->type == PK_PRIVATE || key->type == PK_PRIVATE_OPTIMIZED) &&
        (type == PK_PRIVATE || type == PK_PRIVATE_OPTIMIZED)) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* start at offset y=PACKET_SIZE */
   y = PACKET_SIZE;

   /* output key type */
   out[y++] = type;

   /* output modulus */
   OUTPUT_BIGNUM(&key->N, out, y, z);

   /* output public key */
   OUTPUT_BIGNUM(&key->e, out, y, z);

   if (type == PK_PRIVATE || type == PK_PRIVATE_OPTIMIZED) {
      OUTPUT_BIGNUM(&key->d, out, y, z);
   }

   if (type == PK_PRIVATE_OPTIMIZED) {
      OUTPUT_BIGNUM(&key->dQ, out, y, z);
      OUTPUT_BIGNUM(&key->dP, out, y, z);
      OUTPUT_BIGNUM(&key->pQ, out, y, z);
      OUTPUT_BIGNUM(&key->qP, out, y, z);
      OUTPUT_BIGNUM(&key->p, out, y, z);
      OUTPUT_BIGNUM(&key->q, out, y, z);
   }

   /* store packet header */
   packet_store_header(out, PACKET_SECT_RSA, PACKET_SUB_KEY);

   /* copy to the user buffer */
   *outlen = y;

   /* clear stack and return */
   return CRYPT_OK;
}

int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   unsigned long x, y;
   int err;

   _ARGCHK(in  != NULL);
   _ARGCHK(key != NULL);

   /* check length */
   if (inlen < (1+PACKET_SIZE)) {
      return CRYPT_INVALID_PACKET;
   }

   /* test packet header */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_RSA, PACKET_SUB_KEY)) != CRYPT_OK) {
      return err;
   }

   /* init key */
   if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP,
                     &key->pQ, &key->p, &key->q, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* get key type */
   y = PACKET_SIZE;
   key->type = (int)in[y++];

   /* load the modulus  */
   INPUT_BIGNUM(&key->N, in, x, y);

   /* load public exponent */
   INPUT_BIGNUM(&key->e, in, x, y);

   /* get private exponent */
   if (key->type == PK_PRIVATE || key->type == PK_PRIVATE_OPTIMIZED) {
      INPUT_BIGNUM(&key->d, in, x, y);
   }

   /* get CRT private data if required */
   if (key->type == PK_PRIVATE_OPTIMIZED) {
      INPUT_BIGNUM(&key->dQ, in, x, y);
      INPUT_BIGNUM(&key->dP, in, x, y);
      INPUT_BIGNUM(&key->pQ, in, x, y);
      INPUT_BIGNUM(&key->qP, in, x, y);
      INPUT_BIGNUM(&key->p, in, x, y);
      INPUT_BIGNUM(&key->q, in, x, y);
   }

   /* free up ram not required */
   if (key->type != PK_PRIVATE_OPTIMIZED) {
      mp_clear_multi(&key->dQ, &key->dP, &key->pQ, &key->qP, &key->p, &key->q, NULL);
   }
   if (key->type != PK_PRIVATE && key->type != PK_PRIVATE_OPTIMIZED) {
      mp_clear(&key->d);
   }

   return CRYPT_OK;
error:
   mp_clear_multi(&key->d, &key->e, &key->N, &key->dQ, &key->dP,
                  &key->pQ, &key->qP, &key->p, &key->q, NULL);
   return err;
}

#include "rsa_sys.c"

#endif /* RSA */


