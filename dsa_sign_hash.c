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

#ifdef MDSA

int dsa_sign_hash(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng, dsa_key *key)
{
   mp_int k, kinv, tmp, r, s;
   unsigned char buf[512];
   int err, y;
   unsigned long len;


   _ARGCHK(in     != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key    != NULL);

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

   do {
      /* gen random k */
      if (prng_descriptor[wprng].read(buf, key->qord, prng) != (unsigned long)key->qord) {
         err = CRYPT_ERROR_READPRNG;
         goto done;
      }

      /* read k */
      if ((err = mp_read_unsigned_bin(&k, buf, key->qord)) != MP_OKAY)                { goto error; }

      /* k > 1 ? */
      if (mp_cmp_d(&k, 1) != MP_GT)                                                   { goto retry; }

      /* test gcd */
      if ((err = mp_gcd(&k, &key->q, &tmp)) != MP_OKAY)                               { goto error; }
   } while (mp_cmp_d(&tmp, 1) != MP_EQ);

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
   out[y++] = len&255;
   
   /* store r */
   if ((err = mp_to_unsigned_bin(&r, out+y)) != MP_OKAY)                              { goto error; }
   y += len;

   /* store length of s */
   len = mp_unsigned_bin_size(&s);
   out[y++] = (len>>8)&255;
   out[y++] = len&255;
   
   /* store s */
   if ((err = mp_to_unsigned_bin(&s, out+y)) != MP_OKAY)                              { goto error; }
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

#endif
