#include "mycrypt.h"

#ifdef MRSA

int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key)
{
   mp_int p, q, tmp1, tmp2, tmp3;
   int res, err;

   _ARGCHK(key != NULL);

   if ((size < (1024/8)) || (size > (4096/8))) {
      return CRYPT_INVALID_KEYSIZE;
   }

   if ((e < 3) || ((e & 1) == 0)) {
      return CRYPT_INVALID_ARG;
   }

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   if (mp_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }

   /* make primes p and q (optimization provided by Wayne Scott) */
   if (mp_set_int(&tmp3, e) != MP_OKAY) { goto error; }            /* tmp3 = e */

   /* make prime "p" */
   do {
       if (rand_prime(&p, size/2, prng, wprng) != CRYPT_OK) { res = CRYPT_ERROR; goto done; }
       if (mp_sub_d(&p, 1, &tmp1) != MP_OKAY)              { goto error; }  /* tmp1 = p-1 */
       if (mp_gcd(&tmp1, &tmp3, &tmp2) != MP_OKAY)         { goto error; }  /* tmp2 = gcd(p-1, e) */
   } while (mp_cmp_d(&tmp2, 1) != 0);                                       /* while e divides p-1 */

   /* make prime "q" */
   do {
       if (rand_prime(&q, size/2, prng, wprng) != CRYPT_OK) { res = CRYPT_ERROR; goto done; }
       if (mp_sub_d(&q, 1, &tmp1) != MP_OKAY)              { goto error; } /* tmp1 = q-1 */
       if (mp_gcd(&tmp1, &tmp3, &tmp2) != MP_OKAY)         { goto error; } /* tmp2 = gcd(q-1, e) */
   } while (mp_cmp_d(&tmp2, 1) != 0);                                      /* while e divides q-1 */

   /* tmp1 = lcm(p-1, q-1) */
   if (mp_sub_d(&p, 1, &tmp2) != MP_OKAY)                  { goto error; } /* tmp2 = p-1 */
                                                                           /* tmp1 = q-1 (previous do/while loop) */
   if (mp_lcm(&tmp1, &tmp2, &tmp1) != MP_OKAY)             { goto error; } /* tmp1 = lcm(p-1, q-1) */

   /* make key */
   if (mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP,
                     &key->qP, &key->pQ, &key->p, &key->q, NULL) != MP_OKAY) {
      goto error;
   }

   if (mp_set_int(&key->e, e) != MP_OKAY)                  { goto error2; } /* key->e =  e */
   if (mp_invmod(&key->e, &tmp1, &key->d) != MP_OKAY)      { goto error2; } /* key->d = 1/e mod lcm(p-1,q-1) */
   if (mp_mul(&p, &q, &key->N) != MP_OKAY)                 { goto error2; } /* key->N = pq */

/* optimize for CRT now */
   /* find d mod q-1 and d mod p-1 */
   if (mp_sub_d(&p, 1, &tmp1) != MP_OKAY)                  { goto error2; } /* tmp1 = q-1 */
   if (mp_sub_d(&q, 1, &tmp2) != MP_OKAY)                  { goto error2; } /* tmp2 = p-1 */

   if (mp_mod(&key->d, &tmp1, &key->dP) != MP_OKAY)        { goto error2; } /* dP = d mod p-1 */
   if (mp_mod(&key->d, &tmp2, &key->dQ) != MP_OKAY)        { goto error2; } /* dQ = d mod q-1 */

   if (mp_invmod(&q, &p, &key->qP) != MP_OKAY)             { goto error2; } /* qP = 1/q mod p */
   if (mp_mulmod(&key->qP, &q, &key->N, &key->qP))         { goto error2; } /* qP = q * (1/q mod p) mod N */

   if (mp_invmod(&p, &q, &key->pQ) != MP_OKAY)             { goto error2; } /* pQ = 1/p mod q */
   if (mp_mulmod(&key->pQ, &p, &key->N, &key->pQ))         { goto error2; } /* pQ = p * (1/p mod q) mod N */

   if (mp_copy(&p, &key->p) != MP_OKAY)                    { goto error2; }
   if (mp_copy(&q, &key->q) != MP_OKAY)                    { goto error2; }

   /* shrink ram required  */
   if (mp_shrink(&key->e) != MP_OKAY)                      { goto error2; }
   if (mp_shrink(&key->d) != MP_OKAY)                      { goto error2; }
   if (mp_shrink(&key->N) != MP_OKAY)                      { goto error2; }
   if (mp_shrink(&key->dQ) != MP_OKAY)                     { goto error2; }
   if (mp_shrink(&key->dP) != MP_OKAY)                     { goto error2; }
   if (mp_shrink(&key->qP) != MP_OKAY)                     { goto error2; }
   if (mp_shrink(&key->pQ) != MP_OKAY)                     { goto error2; }
   if (mp_shrink(&key->p) != MP_OKAY)                      { goto error2; }
   if (mp_shrink(&key->q) != MP_OKAY)                      { goto error2; }

   res = CRYPT_OK;
   key->type = PK_PRIVATE_OPTIMIZED;
   goto done;
error2:
   mp_clear_multi(&key->d, &key->e, &key->N, &key->dQ, &key->dP,
                  &key->qP, &key->pQ, &key->p, &key->q, NULL);
error:
   res = CRYPT_MEM;
done:
   mp_clear_multi(&tmp3, &tmp2, &tmp1, &p, &q, NULL);
   return res;
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
   int res;

   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);

   if (which == PK_PRIVATE && (key->type != PK_PRIVATE && key->type != PK_PRIVATE_OPTIMIZED)) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* must be a private or public operation */
   if (which != PK_PRIVATE && which != PK_PUBLIC) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* init and copy into tmp */
   if (mp_init_multi(&tmp, &tmpa, &tmpb, NULL) != MP_OKAY)                          { goto error; }
   if (mp_read_unsigned_bin(&tmp, (unsigned char *)in, (int)inlen) != MP_OKAY)      { goto error; }

   /* sanity check on the input */
   if (mp_cmp(&key->N, &tmp) == MP_LT) {
      res = CRYPT_PK_INVALID_SIZE;
      goto done;
   }

   /* are we using the private exponent and is the key optimized? */
   if (which == PK_PRIVATE && key->type == PK_PRIVATE_OPTIMIZED) {
      /* tmpa = tmp^dP mod p */
      if (mp_exptmod(&tmp, &key->dP, &key->p, &tmpa) != MP_OKAY)    { goto error; }

      /* tmpb = tmp^dQ mod q */
      if (mp_exptmod(&tmp, &key->dQ, &key->q, &tmpb) != MP_OKAY)    { goto error; }

      /* tmp = tmpa*qP + tmpb*pQ mod N */
      if (mp_mul(&tmpa, &key->qP, &tmpa) != MP_OKAY)                { goto error; }
      if (mp_mul(&tmpb, &key->pQ, &tmpb) != MP_OKAY)                { goto error; }
      if (mp_addmod(&tmpa, &tmpb, &key->N, &tmp) != MP_OKAY)        { goto error; }
   } else {
      /* exptmod it */
      if (mp_exptmod(&tmp, which==PK_PRIVATE?&key->d:&key->e, &key->N, &tmp) != MP_OKAY) { goto error; }
   }

   /* read it back */
   x = (unsigned long)mp_unsigned_bin_size(&tmp);
   if (x > *outlen) {
      res = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }
   *outlen = x;

   /* convert it */
   if (mp_to_unsigned_bin(&tmp, out) != MP_OKAY)                    { goto error; }

   /* clean up and return */
   res = CRYPT_OK;
   goto done;
error:
   res = CRYPT_MEM;
done:
   mp_clear_multi(&tmp, &tmpa, &tmpb, NULL);
   return res;
}

int rsa_signpad(const unsigned char *in,  unsigned long inlen,
                      unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y;

   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
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
   unsigned char buf[1536];
   unsigned long x;
   int err;

   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
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
   if (inlen > 512) {
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

   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
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

   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
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

#define OUTPUT_BIGNUM(num, buf2, y, z)         \
{                                              \
      z = (unsigned long)mp_unsigned_bin_size(num);  \
      STORE32L(z, buf2+y);                     \
      y += 4;                                  \
      if (mp_to_unsigned_bin(num, buf2+y) != MP_OKAY) { return CRYPT_MEM; }    \
      y += z;                                  \
}


#define INPUT_BIGNUM(num, in, x, y)                              \
{                                                                \
     /* load value */                                            \
     if (y + 4 > inlen) {                                        \
         err = CRYPT_INVALID_PACKET;                           \
         goto error2;                                            \
     }                                                           \
     LOAD32L(x, in+y);                                           \
     y += 4;                                                     \
                                                                 \
     /* sanity check... */                                       \
     if (y+x > inlen) {                                          \
        err = CRYPT_INVALID_PACKET;                            \
        goto error2;                                             \
     }                                                           \
                                                                 \
     /* load it */                                               \
     if (mp_read_unsigned_bin(num, (unsigned char *)in+y, (int)x) != MP_OKAY) {\
        err = CRYPT_MEM;                                       \
        goto error2;                                             \
     }                                                           \
     y += x;                                                     \
                                                                 \
     if (mp_shrink(num) != MP_OKAY) {                            \
        err = CRYPT_MEM;                                       \
        goto error2;                                             \
     }                                                           \
}

int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key)
{
   unsigned char buf2[5120];
   unsigned long y, z;

   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);

   /* type valid? */
   if (!(key->type == PK_PRIVATE || key->type == PK_PRIVATE_OPTIMIZED) &&
        (type == PK_PRIVATE || type == PK_PRIVATE_OPTIMIZED)) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* start at offset y=PACKET_SIZE */
   y = PACKET_SIZE;

   /* output key type */
   buf2[y++] = type;

   /* output modulus */
   OUTPUT_BIGNUM(&key->N, buf2, y, z);

   /* output public key */
   OUTPUT_BIGNUM(&key->e, buf2, y, z);

   if (type == PK_PRIVATE || type == PK_PRIVATE_OPTIMIZED) {
      OUTPUT_BIGNUM(&key->d, buf2, y, z);
   }

   if (type == PK_PRIVATE_OPTIMIZED) {
      OUTPUT_BIGNUM(&key->dQ, buf2, y, z);
      OUTPUT_BIGNUM(&key->dP, buf2, y, z);
      OUTPUT_BIGNUM(&key->pQ, buf2, y, z);
      OUTPUT_BIGNUM(&key->qP, buf2, y, z);
      OUTPUT_BIGNUM(&key->p, buf2, y, z);
      OUTPUT_BIGNUM(&key->q, buf2, y, z);
   }

   /* check size */
   if (*outlen < y) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* store packet header */
   packet_store_header(buf2, PACKET_SECT_RSA, PACKET_SUB_KEY);

   /* copy to the user buffer */
   memcpy(out, buf2, (size_t)y);
   *outlen = y;

   /* clear stack and return */
#ifdef CLEAN_STACK
   zeromem(buf2, sizeof(buf2));
#endif
   return CRYPT_OK;
}

int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   unsigned long x, y;
   int err;

   _ARGCHK(in != NULL);
   _ARGCHK(key != NULL);

   /* check length */
   if (inlen < 1+PACKET_SIZE) {
      return CRYPT_INVALID_PACKET;
   }

   /* test packet header */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_RSA, PACKET_SUB_KEY)) != CRYPT_OK) {
      return err;
   }

   /* init key */
   if (mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP,
                     &key->pQ, &key->p, &key->q, NULL) != MP_OKAY) {
      return CRYPT_MEM;
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
error2:
   mp_clear_multi(&key->d, &key->e, &key->N, &key->dQ, &key->dP,
                  &key->pQ, &key->qP, &key->p, &key->q, NULL);
   return err;
}

#include "rsa_sys.c"

#endif /* RSA */


