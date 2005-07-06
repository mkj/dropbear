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
  @file rsa_import.c
  Import a PKCS RSA key, Tom St Denis
*/  

#ifdef MRSA

/**
  Import an RSAPublicKey or RSAPrivateKey [two-prime only, only support >= 1024-bit keys, defined in PKCS #1 v2.1]
  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   int           err;
   mp_int        zero;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   /* init key */
   if ((err = mp_init_multi(&zero, &key->e, &key->d, &key->N, &key->dQ, 
                            &key->dP, &key->qP, &key->p, &key->q, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   if ((err = der_decode_sequence_multi(in, inlen, 
                                  LTC_ASN1_INTEGER, 1UL, &key->N, 
                                  LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   if (mp_cmp_d(&key->N, 0) == MP_EQ) {
      /* it's a private key */
      if ((err = der_decode_sequence_multi(in, inlen, 
                          LTC_ASN1_INTEGER, 1UL, &zero, 
                          LTC_ASN1_INTEGER, 1UL, &key->N, 
                          LTC_ASN1_INTEGER, 1UL, &key->e,
                          LTC_ASN1_INTEGER, 1UL, &key->d, 
                          LTC_ASN1_INTEGER, 1UL, &key->p, 
                          LTC_ASN1_INTEGER, 1UL, &key->q, 
                          LTC_ASN1_INTEGER, 1UL, &key->dP,
                          LTC_ASN1_INTEGER, 1UL, &key->dQ, 
                          LTC_ASN1_INTEGER, 1UL, &key->qP, 
                          LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
         goto LBL_ERR;
      }
      key->type = PK_PRIVATE;
   } else if (mp_cmp_d(&key->N, 1) == MP_EQ) {
      /* we don't support multi-prime RSA */
      err = CRYPT_PK_INVALID_TYPE;
      goto LBL_ERR;
   } else {
      /* it's a public key and we lack e */
      if ((err = der_decode_sequence_multi(in, inlen, 
                                     LTC_ASN1_INTEGER, 1UL, &key->N, 
                                     LTC_ASN1_INTEGER, 1UL, &key->e, 
                                     LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
         goto LBL_ERR;
      }

      /* free up some ram */
      mp_clear_multi(&key->p, &key->q, &key->qP, &key->dP, &key->dQ, NULL);
      key->type = PK_PUBLIC;
   }
   return CRYPT_OK;
LBL_ERR:
   mp_clear_multi(&zero, &key->d, &key->e, &key->N, &key->dQ, &key->dP,
                  &key->qP, &key->p, &key->q, NULL);
   return err;
}

#endif /* MRSA */


/* $Source: /cvs/libtom/libtomcrypt/src/pk/rsa/rsa_import.c,v $ */
/* $Revision: 1.10 $ */
/* $Date: 2005/06/03 18:48:28 $ */
