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

#ifdef MRSA

/* import an RSAPublicKey or RSAPrivateKey [two-prime only, defined in PKCS #1 v2.1] */
int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   unsigned long x;
   int err;

   _ARGCHK(in  != NULL);
   _ARGCHK(key != NULL);

   /* init key */
   if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP,
                     &key->p, &key->q, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* read first number, it's either N or 0 [0 == private key] */
   x = inlen;
   if ((err = der_get_multi_integer(in, &x, &key->N, NULL)) != CRYPT_OK) {
      goto __ERR;
   }

   /* advance */
   inlen -= x;
   in    += x;

   if (mp_cmp_d(&key->N, 0) == MP_EQ) {
      /* it's a private key */
      if ((err = der_get_multi_integer(in, &inlen, &key->N, &key->e,
                          &key->d, &key->p, &key->q, &key->dP,
                          &key->dQ, &key->qP, NULL)) != CRYPT_OK) {
         goto __ERR;
      }

      key->type = PK_PRIVATE;
   } else {
      /* it's a public key and we lack e */
      if ((err = der_get_multi_integer(in, &inlen, &key->e, NULL)) != CRYPT_OK) {
         goto __ERR;
      }

      /* free up some ram */
      mp_clear_multi(&key->p, &key->q, &key->qP, &key->dP, &key->dQ, NULL);

      key->type = PK_PUBLIC;
   }
   return CRYPT_OK;
__ERR:
   mp_clear_multi(&key->d, &key->e, &key->N, &key->dQ, &key->dP,
                  &key->qP, &key->p, &key->q, NULL);
   return err;
}

#endif /* MRSA */

