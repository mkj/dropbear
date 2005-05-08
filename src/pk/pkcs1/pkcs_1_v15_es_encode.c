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
  @file pkcs_1_v15_es_encode.c
  v1.5 Encryption Padding for PKCS #1, Tom St Denis 
*/

#ifdef PKCS_1

/**
  PKCS #1 v1.5 Encryption Padding
  @param msg            The data to encode
  @param msglen         The length of the data (octets)
  @param modulus_bitlen The bit length of the RSA modulus
  @param prng           An active PRNG
  @param prng_idx       The index of the PRNG desired
  @param out            [out] The destination of the padding
  @param outlen         [in/out] The max size and resulting size of the padding
  @return CRYPT_OK if successful
*/
int pkcs_1_v15_es_encode(const unsigned char *msg,    unsigned long msglen,
                               unsigned long  modulus_bitlen, 
                               prng_state    *prng,   int           prng_idx,
                               unsigned char *out,    unsigned long *outlen)
{ 
   unsigned long modulus_bytelen, x, y;

   LTC_ARGCHK(msg    != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* get modulus len */
   modulus_bytelen = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);
   if (modulus_bytelen < 12) {
      return CRYPT_INVALID_ARG;
   }

   /* verify length */
   if (msglen > (modulus_bytelen - 11) || *outlen < modulus_bytelen) {
      return CRYPT_PK_INVALID_SIZE;
   }

   /* 0x00 0x02 PS 0x00 M */
   x = 0;
   out[x++] = 0x00;
   out[x++] = 0x02;
   y = modulus_bytelen - msglen - 3;
   if (prng_descriptor[prng_idx].read(out+x, y, prng) != y) {
      return CRYPT_ERROR_READPRNG;
   }
   x += y;
   out[x++] = 0x00;
   XMEMCPY(out+x, msg, msglen);
   *outlen = modulus_bytelen;

   return CRYPT_OK;
}

#endif /* PKCS_1 */
