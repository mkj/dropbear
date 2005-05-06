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
   @file dsa_verify_key.c
   DSA implementation, verify a key, Tom St Denis
*/

#ifdef MDSA

/**
   Verify a DSA key for validity
   @param key   The key to verify
   @param stat  [out]  Result of test, 1==valid, 0==invalid
   @return CRYPT_OK if successful
*/
int dsa_verify_key(dsa_key *key, int *stat)
{
   mp_int tmp, tmp2;
   int    res, err;

   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(stat != NULL);

   /* default to an invalid key */
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
