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

/* This will export either an RSAPublicKey or RSAPrivateKey [defined in PKCS #1 v2.1] */
int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key)
{
   int err;

   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key    != NULL);

   /* type valid? */
   if (!(key->type == PK_PRIVATE) && (type == PK_PRIVATE)) {
      return CRYPT_PK_INVALID_TYPE;
   }
  
   if (type == PK_PRIVATE) {
      /* private key */
      mp_int zero;

      /* first INTEGER == 0 to signify two-prime RSA */
      if ((err = mp_init(&zero)) != MP_OKAY) {
         return mpi_to_ltc_error(err);
      }
 
      /* output is 
            Version, n, e, d, p, q, d mod (p-1), d mod (q - 1), 1/q mod p
       */
      err = der_put_multi_integer(out, outlen, &zero, &key->N, &key->e,
                          &key->d, &key->p, &key->q, &key->dP,
                          &key->dQ, &key->qP, NULL);
 
      /* clear zero and return */
      mp_clear(&zero);
      return err;
   } else {
      /* public key */
      return der_put_multi_integer(out, outlen, &key->N, &key->e, NULL);
   }
}

#endif /* MRSA */

