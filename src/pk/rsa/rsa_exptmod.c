/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */
#include "tomcrypt.h"

/**
  @file rsa_exptmod.c
  RSA PKCS exptmod, Tom St Denis
*/  

#ifdef MRSA

/** 
   Compute an RSA modular exponentiation 
   @param in         The input data to send into RSA
   @param inlen      The length of the input (octets)
   @param out        [out] The destination 
   @param outlen     [in/out] The max size and resulting size of the output
   @param which      Which exponent to use, e.g. PK_PRIVATE or PK_PUBLIC
   @param key        The RSA key to use 
   @return CRYPT_OK if successful
*/   
int rsa_exptmod(const unsigned char *in,   unsigned long inlen,
                      unsigned char *out,  unsigned long *outlen, int which,
                      rsa_key *key)
{
   mp_int        tmp, tmpa, tmpb;
   unsigned long x;
   int           err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);
   
   /* is the key of the right type for the operation? */
   if (which == PK_PRIVATE && (key->type != PK_PRIVATE)) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* must be a private or public operation */
   if (which != PK_PRIVATE && which != PK_PUBLIC) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* init and copy into tmp */
   if ((err = mp_init_multi(&tmp, &tmpa, &tmpb, NULL)) != MP_OKAY)                                    { return mpi_to_ltc_error(err); }
   if ((err = mp_read_unsigned_bin(&tmp, (unsigned char *)in, (int)inlen)) != MP_OKAY)                { goto error; }

   /* sanity check on the input */
   if (mp_cmp(&key->N, &tmp) == MP_LT) {
      err = CRYPT_PK_INVALID_SIZE;
      goto done;
   }

   /* are we using the private exponent and is the key optimized? */
   if (which == PK_PRIVATE) {
      /* tmpa = tmp^dP mod p */
      if ((err = mp_exptmod(&tmp, &key->dP, &key->p, &tmpa)) != MP_OKAY)                               { goto error; }

      /* tmpb = tmp^dQ mod q */
      if ((err = mp_exptmod(&tmp, &key->dQ, &key->q, &tmpb)) != MP_OKAY)                               { goto error; }

      /* tmp = (tmpa - tmpb) * qInv (mod p) */
      if ((err = mp_sub(&tmpa, &tmpb, &tmp)) != MP_OKAY)                                              { goto error; }
      if ((err = mp_mulmod(&tmp, &key->qP, &key->p, &tmp)) != MP_OKAY)                                { goto error; }

      /* tmp = tmpb + q * tmp */
      if ((err = mp_mul(&tmp, &key->q, &tmp)) != MP_OKAY)                                             { goto error; }
      if ((err = mp_add(&tmp, &tmpb, &tmp)) != MP_OKAY)                                               { goto error; }
   } else {
      /* exptmod it */
      if ((err = mp_exptmod(&tmp, &key->e, &key->N, &tmp)) != MP_OKAY)                                { goto error; }
   }

   /* read it back */
   x = (unsigned long)mp_unsigned_bin_size(&key->N);
   if (x > *outlen) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }
   *outlen = x;

   /* convert it */
   zeromem(out, x);
   if ((err = mp_to_unsigned_bin(&tmp, out+(x-mp_unsigned_bin_size(&tmp)))) != MP_OKAY)               { goto error; }

   /* clean up and return */
   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&tmp, &tmpa, &tmpb, NULL);
   return err;
}

#endif
