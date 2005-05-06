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
   @file dsa_verify_hash.c
   DSA implementation, verify a signature, Tom St Denis
*/


#ifdef MDSA

/**
  Verify a DSA signature
  @param sig      The signature
  @param siglen   The length of the signature (octets)
  @param hash     The hash that was signed
  @param hashlen  The length of the hash that was signed
  @param stat     [out] The result of the signature verification, 1==valid, 0==invalid
  @param key      The corresponding public DH key
  @return CRYPT_OK if successful (even if the signature is invalid)
*/
int dsa_verify_hash(const unsigned char *sig, unsigned long siglen,
                    const unsigned char *hash, unsigned long hashlen, 
                    int *stat, dsa_key *key)
{
   mp_int        r, s, w, v, u1, u2;
   int           err;

   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(hash != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(key  != NULL);

   /* default to invalid signature */
   *stat = 0;

   /* init our variables */
   if ((err = mp_init_multi(&r, &s, &w, &v, &u1, &u2, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* read in r followed by s */
   if ((err = der_get_multi_integer(sig, &siglen, &r, &s, NULL)) != CRYPT_OK)              { goto done; }

   /* neither r or s can be null */
   if (mp_iszero(&r) == MP_YES || mp_iszero(&s) == MP_YES) {
      err = CRYPT_INVALID_PACKET;
      goto done;
   }
   
   /* w = 1/s mod q */
   if ((err = mp_invmod(&s, &key->q, &w)) != MP_OKAY)                                      { goto error; }

   /* u1 = m * w mod q */
   if ((err = mp_read_unsigned_bin(&u1, (unsigned char *)hash, hashlen)) != MP_OKAY)       { goto error; }
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

#endif

