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

int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   unsigned long x, y;
   int err;

   _ARGCHK(in  != NULL);
   _ARGCHK(key != NULL);

   /* check length */
   if (inlen < (1+PACKET_SIZE)) {
      return CRYPT_INVALID_PACKET;
   }

   /* test packet header */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_RSA, PACKET_SUB_KEY)) != CRYPT_OK) {
      return err;
   }

   /* init key */
   if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP,
                     &key->pQ, &key->p, &key->q, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* get key type */
   y = PACKET_SIZE;
   key->type = (int)in[y++];

   /* load the modulus  */
   INPUT_BIGNUM(&key->N, in, x, y, inlen);

   /* load public exponent */
   INPUT_BIGNUM(&key->e, in, x, y, inlen);

   /* get private exponent */
   if (key->type == PK_PRIVATE || key->type == PK_PRIVATE_OPTIMIZED) {
      INPUT_BIGNUM(&key->d, in, x, y, inlen);
   }

   /* get CRT private data if required */
   if (key->type == PK_PRIVATE_OPTIMIZED) {
      INPUT_BIGNUM(&key->dQ, in, x, y, inlen);
      INPUT_BIGNUM(&key->dP, in, x, y, inlen);
      INPUT_BIGNUM(&key->pQ, in, x, y, inlen);
      INPUT_BIGNUM(&key->qP, in, x, y, inlen);
      INPUT_BIGNUM(&key->p, in, x, y, inlen);
      INPUT_BIGNUM(&key->q, in, x, y, inlen);
   }

   /* free up ram not required */
   if (key->type != PK_PRIVATE_OPTIMIZED) {
      mp_clear_multi(&key->dQ, &key->dP, &key->pQ, &key->qP, &key->p, &key->q, NULL);
   }
   if (key->type != PK_PRIVATE && key->type != PK_PRIVATE_OPTIMIZED) {
      mp_clear(&key->d);
   }

   return CRYPT_OK;
error:
   mp_clear_multi(&key->d, &key->e, &key->N, &key->dQ, &key->dP,
                  &key->pQ, &key->qP, &key->p, &key->q, NULL);
   return err;
}

#endif /* MRSA */

