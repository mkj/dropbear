#include "mycrypt.h"

#ifdef MDSA

#define DRAW(x) { char __buf[1000]; mp_toradix(x, __buf, 16); printf("\n%s == %s\n", #x, __buf); }

int dsa_make_key(prng_state *prng, int wprng, int group_size, int modulus_size, dsa_key *key)
{
   mp_int tmp, tmp2;
   int err, res;
   unsigned char buf[512];

   _ARGCHK(prng != NULL);
   _ARGCHK(key  != NULL);

   /* check prng */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* check size */
   if (group_size >= 1024 || group_size <= 15 || 
       group_size >= modulus_size || (modulus_size - group_size) >= (int)sizeof(buf)) {
      return CRYPT_INVALID_ARG;
   }

   /* init mp_ints  */
   if ((err = mp_init_multi(&tmp, &tmp2, &key->g, &key->q, &key->p, &key->x, &key->y, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* make our prime q */
   if ((err = rand_prime(&key->q, group_size, prng, wprng)) != CRYPT_OK)             { goto error2; }

   /* double q  */
   if ((err = mp_mul_2(&key->q, &tmp)) != MP_OKAY)                                   { goto error; }

   /* now make a random string and multply it against q */
   if (prng_descriptor[wprng].read(buf, modulus_size - group_size, prng) != (unsigned long)(modulus_size - group_size)) {
      err = CRYPT_ERROR_READPRNG;
      goto error2;
   }

   /* force magnitude */
   buf[0] |= 0x80;

   /* force even */
   buf[modulus_size - group_size - 1] &= ~1;

   if ((err = mp_read_unsigned_bin(&tmp2, buf, modulus_size - group_size)) != MP_OKAY) { goto error; }
   if ((err = mp_mul(&key->q, &tmp2, &key->p)) != MP_OKAY)                             { goto error; }
   if ((err = mp_add_d(&key->p, 1, &key->p)) != MP_OKAY)                               { goto error; }
   
   /* now loop until p is prime */
   for (;;) {
       if ((err = is_prime(&key->p, &res)) != CRYPT_OK)                                { goto error2; }
       if (res == MP_YES) break;

       /* add 2q to p and 2 to tmp2 */
       if ((err = mp_add(&tmp, &key->p, &key->p)) != MP_OKAY)                          { goto error; }
       if ((err = mp_add_d(&tmp2, 2, &tmp2)) != MP_OKAY)                               { goto error; }
   }

   /* now p = (q * tmp2) + 1 is prime, find a value g for which g^tmp2 != 1 */
   mp_set(&key->g, 1);

   do {
      if ((err = mp_add_d(&key->g, 1, &key->g)) != MP_OKAY)                            { goto error; }
      if ((err = mp_exptmod(&key->g, &tmp2, &key->p, &tmp)) != MP_OKAY)                { goto error; }
   } while (mp_cmp_d(&tmp, 1) == MP_EQ);

   /* at this point tmp generates a group of order q mod p */
   mp_exch(&tmp, &key->g);

   /* so now we have our DH structure, generator g, order q, modulus p 
      Now we need a random exponent [mod q] and it's power g^x mod p 
    */
   do {
      if (prng_descriptor[wprng].read(buf, group_size, prng) != (unsigned long)group_size) {
         err = CRYPT_ERROR_READPRNG;
         goto error2;
      }
      if ((err = mp_read_unsigned_bin(&key->x, buf, group_size)) != MP_OKAY)              { goto error; }
   } while (mp_cmp_d(&key->x, 1) != MP_GT);
   if ((err = mp_exptmod(&key->g, &key->x, &key->p, &key->y)) != MP_OKAY)              { goto error; }
   
   key->type = PK_PRIVATE;
   key->qord = group_size;

   /* shrink the ram required */
   if ((err = mp_shrink(&key->g)) != MP_OKAY)                                          { goto error; }
   if ((err = mp_shrink(&key->p)) != MP_OKAY)                                          { goto error; }
   if ((err = mp_shrink(&key->q)) != MP_OKAY)                                          { goto error; }
   if ((err = mp_shrink(&key->x)) != MP_OKAY)                                          { goto error; }
   if ((err = mp_shrink(&key->y)) != MP_OKAY)                                          { goto error; }

   err = CRYPT_OK;

#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif

   goto done;
error : err = mpi_to_ltc_error(err);
error2: mp_clear_multi(&key->g, &key->q, &key->p, &key->x, &key->y, NULL);
done  : mp_clear_multi(&tmp, &tmp2, NULL);
   return err;
}

void dsa_free(dsa_key *key)
{
   _ARGCHK(key != NULL);
   mp_clear_multi(&key->g, &key->q, &key->p, &key->x, &key->y, NULL);
}


int dsa_sign_hash(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng, dsa_key *key)
{
   mp_int k, kinv, tmp, r, s;
   unsigned char buf[512];
   int err, y;
   unsigned long len;


   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(prng != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* check group order size  */
   if (key->qord >= (int)sizeof(buf)) {
      return CRYPT_INVALID_ARG;
   }

   /* Init our temps */
   if ((err = mp_init_multi(&k, &kinv, &r, &s, &tmp, NULL)) != MP_OKAY)               { goto error; }

retry:
   /* gen random k */
   if (prng_descriptor[wprng].read(buf, key->qord, prng) != (unsigned long)key->qord) {
      err = CRYPT_ERROR_READPRNG;
      goto done;
   }

   /* read k */
   if ((err = mp_read_unsigned_bin(&k, buf, key->qord)) != MP_OKAY)                   { goto error; }

   /* now find 1/k mod q */
   if ((err = mp_invmod(&k, &key->q, &kinv)) != MP_OKAY)                              { goto error; }

   /* now find r = g^k mod p mod q */
   if ((err = mp_exptmod(&key->g, &k, &key->p, &r)) != MP_OKAY)                       { goto error; }
   if ((err = mp_mod(&r, &key->q, &r)) != MP_OKAY)                                    { goto error; }

   if (mp_iszero(&r) == MP_YES)                                                       { goto retry; }

   /* now find s = (in + xr)/k mod q */
   if ((err = mp_read_unsigned_bin(&tmp, (unsigned char *)in, inlen)) != MP_OKAY)     { goto error; }
   if ((err = mp_mul(&key->x, &r, &s)) != MP_OKAY)                                    { goto error; }
   if ((err = mp_add(&s, &tmp, &s)) != MP_OKAY)                                       { goto error; }
   if ((err = mp_mulmod(&s, &kinv, &key->q, &s)) != MP_OKAY)                          { goto error; }

   if (mp_iszero(&s) == MP_YES)                                                       { goto retry; }

   /* now store em both */
   
   /* first check that we have enough room */
   if (*outlen < (unsigned long)(PACKET_SIZE + 4 + mp_unsigned_bin_size(&s) + mp_unsigned_bin_size(&r))) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }

   /* packet header */
   packet_store_header(out, PACKET_SECT_DSA, PACKET_SUB_SIGNED);
   y = PACKET_SIZE;

   /* store length of r */
   len = mp_unsigned_bin_size(&r);
   out[y++] = (len>>8)&255;
   out[y++] = (len & 255);
   
   /* store r */
   mp_to_unsigned_bin(&r, out+y);
   y += len;

   /* store length of s */
   len = mp_unsigned_bin_size(&s);
   out[y++] = (len>>8)&255;
   out[y++] = (len & 255);
   
   /* store s */
   mp_to_unsigned_bin(&s, out+y);
   y += len;

   /* reset size */
   *outlen = y;

   err = CRYPT_OK;
   goto done;

error : err = mpi_to_ltc_error(err);
done  : mp_clear_multi(&k, &kinv, &r, &s, &tmp, NULL);
#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return err;
}

int dsa_verify_hash(const unsigned char *sig, unsigned long siglen,
                    const unsigned char *hash, unsigned long inlen, 
                    int *stat, dsa_key *key)
{
   mp_int r, s, w, v, u1, u2;
   unsigned long x, y;
   int err;

   _ARGCHK(sig != NULL);
   _ARGCHK(hash != NULL);
   _ARGCHK(stat != NULL);
   _ARGCHK(key != NULL);

   /* default to invalid signature */
   *stat = 0;

   if (siglen < PACKET_SIZE+2+2) {
      return CRYPT_INVALID_PACKET;
   } 

   /* is the message format correct? */
   if ((err = packet_valid_header((unsigned char *)sig, PACKET_SECT_DSA, PACKET_SUB_SIGNED)) != CRYPT_OK) {
      return err;
   }

   /* skip over header */
   y = PACKET_SIZE;

   /* init our variables */
   if ((err = mp_init_multi(&r, &s, &w, &v, &u1, &u2, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* read in r followed by s */
   x = ((unsigned)sig[y]<<8)|((unsigned)sig[y+1]);
   y += 2;
   if (y + x > siglen) { 
      err = CRYPT_INVALID_PACKET;
      goto done;
   }
   if ((err = mp_read_unsigned_bin(&r, (unsigned char *)sig+y, x)) != MP_OKAY)             { goto error; }
   y += x;

   /* load s */
   x = ((unsigned)sig[y]<<8)|((unsigned)sig[y+1]);
   y += 2;
   if (y + x > siglen) { 
      err = CRYPT_INVALID_PACKET;
      goto done;
   }
   if ((err = mp_read_unsigned_bin(&s, (unsigned char *)sig+y, x)) != MP_OKAY)             { goto error; }

   /* w = 1/s mod q */
   if ((err = mp_invmod(&s, &key->q, &w)) != MP_OKAY)                                      { goto error; }

   /* u1 = m * w mod q */
   if ((err = mp_read_unsigned_bin(&u1, (unsigned char *)hash, inlen)) != MP_OKAY)         { goto error; }
   if ((err = mp_mulmod(&u1, &w, &key->q, &u1)) != MP_OKAY)                                { goto error; }

   /* u2 = r*w mod q */
   if ((err = mp_mulmod(&r, &w, &key->q, &u2)) != MP_OKAY)                                 { goto error; } 

   /* v = g^u1 * y^u2 mod p mod q */
   if ((err = mp_exptmod(&key->g, &u1, &key->p, &u1)) != MP_OKAY)                          { goto error; }
   if ((err = mp_exptmod(&key->y, &u2, &key->p, &u2)) != MP_OKAY)                          { goto error; }
   if ((err = mp_mulmod(&u1, &u2, &key->p, &v)) != MP_OKAY)                                { goto error; }
   if ((err = mp_mod(&v, &key->q, &v)) != MP_OKAY)                                         { goto error; }

   /* if r = v then we're set */
   if (mp_cmp(&r, &v) == MP_EQ) {
      *stat = 1;
   }

   err = CRYPT_OK;
   goto done;

error : err = mpi_to_ltc_error(err);
done  : mp_clear_multi(&r, &s, &w, &v, &u1, &u2, NULL);
   return err;
}

#define OUTPUT_BIGNUM(num, buf2, y, z)         \
{                                              \
      z = (unsigned long)mp_unsigned_bin_size(num);  \
      if ((y + 4 + z) > *outlen) { return CRYPT_BUFFER_OVERFLOW; } \
      STORE32L(z, out+y);                     \
      y += 4;                                  \
      if (mp_to_unsigned_bin(num, out+y) != MP_OKAY) { return CRYPT_MEM; }  \
      y += z;                                  \
}

int dsa_export(unsigned char *out, unsigned long *outlen, int type, dsa_key *key)
{
   unsigned long y, z;

   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);

   if (type == PK_PRIVATE && key->type != PK_PRIVATE) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   if (type != PK_PUBLIC && type != PK_PRIVATE) {
      return CRYPT_INVALID_ARG;
   }

   /* can we store the static header?  */
   if (*outlen < (PACKET_SIZE + 1 + 2)) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* store header */
   packet_store_header(out, PACKET_SECT_DSA, PACKET_SUB_KEY);
   y = PACKET_SIZE;

   /* store g, p, q, qord */
   out[y++] = type;
   out[y++] = (key->qord>>8)&255;
   out[y++] = key->qord & 255;

   OUTPUT_BIGNUM(&key->g,out,y,z);
   OUTPUT_BIGNUM(&key->p,out,y,z);
   OUTPUT_BIGNUM(&key->q,out,y,z);

   /* public exponent */
   OUTPUT_BIGNUM(&key->y,out,y,z);
   
   if (type == PK_PRIVATE) {
      OUTPUT_BIGNUM(&key->x,out,y,z);
   }

   *outlen = y;
   return CRYPT_OK;
}

#define INPUT_BIGNUM(num, in, x, y)                              \
{                                                                \
     /* load value */                                            \
     if (y+4 > inlen) {                                          \
        err = CRYPT_INVALID_PACKET;                              \
        goto error;                                              \
     }                                                           \
     LOAD32L(x, in+y);                                           \
     y += 4;                                                     \
                                                                 \
     /* sanity check... */                                       \
     if (y+x > inlen) {                                          \
        err = CRYPT_INVALID_PACKET;                              \
        goto error;                                              \
     }                                                           \
                                                                 \
     /* load it */                                               \
     if (mp_read_unsigned_bin(num, (unsigned char *)in+y, (int)x) != MP_OKAY) {\
        err = CRYPT_MEM;                                         \
        goto error;                                              \
     }                                                           \
     y += x;                                                     \
     if (mp_shrink(num) != MP_OKAY) {                            \
        err = CRYPT_MEM;                                         \
        goto error;                                              \
     }                                                           \
}

int dsa_import(const unsigned char *in, unsigned long inlen, dsa_key *key)
{
   unsigned long x, y;
   int err;

   _ARGCHK(in != NULL);
   _ARGCHK(key != NULL);

   /* check length */
   if ((1+2+PACKET_SIZE) > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   /* check type */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_DSA, PACKET_SUB_KEY)) != CRYPT_OK) {
      return err;
   }
   y = PACKET_SIZE;

   /* init key */
   if (mp_init_multi(&key->p, &key->g, &key->q, &key->x, &key->y, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }

   /* read type/qord */
   key->type = in[y++];
   key->qord = ((unsigned)in[y]<<8)|((unsigned)in[y+1]);
   y += 2;

   /* input publics */
   INPUT_BIGNUM(&key->g,in,x,y);
   INPUT_BIGNUM(&key->p,in,x,y);
   INPUT_BIGNUM(&key->q,in,x,y);
   INPUT_BIGNUM(&key->y,in,x,y);
   if (key->type == PK_PRIVATE) {
      INPUT_BIGNUM(&key->x,in,x,y);
   }

   return CRYPT_OK;
error: 
   mp_clear_multi(&key->p, &key->g, &key->q, &key->x, &key->y, NULL);
   return err;
}

int dsa_verify_key(dsa_key *key, int *stat)
{
   mp_int tmp, tmp2;
   int res, err;

   _ARGCHK(key != NULL);
   _ARGCHK(stat != NULL);

   *stat = 0;

   /* first make sure key->q and key->p are prime */
   if ((err = is_prime(&key->q, &res)) != CRYPT_OK) {
      return err;
   }
   if (res == 0) {
      return CRYPT_OK;
   }


   if ((err = is_prime(&key->p, &res)) != CRYPT_OK) {
      return err;
   }
   if (res == 0) {
      return CRYPT_OK;
   }

   /* now make sure that g is not -1, 0 or 1 and <p */
   if (mp_cmp_d(&key->g, 0) == MP_EQ || mp_cmp_d(&key->g, 1) == MP_EQ) {
      return CRYPT_OK;
   }
   if ((err = mp_init_multi(&tmp, &tmp2, NULL)) != MP_OKAY)               { goto error; }
   if ((err = mp_sub_d(&key->p, 1, &tmp)) != MP_OKAY)                     { goto error; }
   if (mp_cmp(&tmp, &key->g) == MP_EQ || mp_cmp(&key->g, &key->p) != MP_LT) {
      err = CRYPT_OK;
      goto done;
   }

   /* 1 < y < p-1 */
   if (!(mp_cmp_d(&key->y, 1) == MP_GT && mp_cmp(&key->y, &tmp) == MP_LT)) {
      err = CRYPT_OK;
      goto done;
   }

   /* now we have to make sure that g^q = 1, and that p-1/q gives 0 remainder */
   if ((err = mp_div(&tmp, &key->q, &tmp, &tmp2)) != MP_OKAY)             { goto error; }
   if (mp_iszero(&tmp2) != MP_YES) {
      err = CRYPT_OK;
      goto done;
   }

   if ((err = mp_exptmod(&key->g, &key->q, &key->p, &tmp)) != MP_OKAY)    { goto error; }
   if (mp_cmp_d(&tmp, 1) != MP_EQ) {
      err = CRYPT_OK;
      goto done;
   }

   /* now we have to make sure that y^q = 1, this makes sure y \in g^x mod p */
   if ((err = mp_exptmod(&key->y, &key->q, &key->p, &tmp)) != MP_OKAY)       { goto error; }
   if (mp_cmp_d(&tmp, 1) != MP_EQ) {
      err = CRYPT_OK;
      goto done;
   }

   /* at this point we are out of tests ;-( */
   err   = CRYPT_OK;
   *stat = 1;
   goto done;
error: err = mpi_to_ltc_error(err);
done : mp_clear_multi(&tmp, &tmp2, NULL);
   return err;
}
#endif
