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
  Import an RSAPublicKey or RSAPrivateKey [two-prime only, defined in PKCS #1 v2.1]
  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   unsigned long x, y;
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   /* init key */
   if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP,
                     &key->p, &key->q, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* check the header */
   if (inlen < 4) {
      return CRYPT_INVALID_PACKET;
   }

   /* should be 0x30 0x8{1|2} LL LL */
   if ((in[0] != 0x30) || ((in[1] != 0x81) && (in[1] != 0x82))) {
      return CRYPT_INVALID_PACKET;
   }

   /* ok all the ASN.1 params are fine so far, let's move up */
   x = ((unsigned long)in[2]);
   y = 0;
   if ((in[1] & ~0x80) == 2) {
      x   = (x << 8) + ((unsigned long)in[3]) + 1;
      in += 1;
      y   = 1;
   }
   in += 3; /* advance input */
   x  += 3; /* size of packet according to header */
   y  += 3; /* used input */

   if (x != inlen) {
      return CRYPT_INVALID_PACKET;
   }
   
   /* decrement inlen by the header size */
   inlen -= y;

   /* read first number, it's either N or 0 [0 == private key] */
   x = inlen;
   if ((err = der_get_multi_integer(in, &x, &key->N, NULL)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* advance */
   inlen -= x;
   in    += x;

   if (mp_cmp_d(&key->N, 0) == MP_EQ) {
      /* it's a private key */
      if ((err = der_get_multi_integer(in, &inlen, &key->N, &key->e,
                          &key->d, &key->p, &key->q, &key->dP,
                          &key->dQ, &key->qP, NULL)) != CRYPT_OK) {
         goto LBL_ERR;
      }

      key->type = PK_PRIVATE;
   } else if (mp_cmp_d(&key->N, 1) == MP_EQ) {
      /* we don't support multi-prime RSA */
      err = CRYPT_PK_INVALID_TYPE;
      goto LBL_ERR;
   } else {
      /* it's a public key and we lack e */
      if ((err = der_get_multi_integer(in, &inlen, &key->e, NULL)) != CRYPT_OK) {
         goto LBL_ERR;
      }

      /* free up some ram */
      mp_clear_multi(&key->p, &key->q, &key->qP, &key->dP, &key->dQ, NULL);

      key->type = PK_PUBLIC;
   }
   return CRYPT_OK;
LBL_ERR:
   mp_clear_multi(&key->d, &key->e, &key->N, &key->dQ, &key->dP,
                  &key->qP, &key->p, &key->q, NULL);
   return err;
}

#endif /* MRSA */

