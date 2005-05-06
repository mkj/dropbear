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
  @file pkcs_1_v15_es_decode.c
  PKCS #1 v1.5 Encryption Padding, Tom St Denis 
*/

#ifdef PKCS_1

/**
  PKCS #1 v1.5 Encryption Decoding
  @param msg             The padded data
  @param msglen          The length of the padded data (octets)
  @param modulus_bitlen  The bit length of the RSA modulus
  @param out             [out] Where to store the decoded data
  @param outlen          The length of the decoded data
  @param res             [out] Result of the decoding, 1==valid, 0==invalid
  @return CRYPT_OK if successful
*/
int pkcs_1_v15_es_decode(const unsigned char *msg,  unsigned long msglen,
                               unsigned long modulus_bitlen,
                               unsigned char *out,  unsigned long outlen,
                               int           *res)
{
   unsigned long x, modulus_bytelen;

   LTC_ARGCHK(msg != NULL);
   LTC_ARGCHK(out != NULL);
   LTC_ARGCHK(res != NULL);
   
   /* default to failed */
   *res = 0;

   modulus_bytelen = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

   /* must be at least modulus_bytelen bytes long */
   if (msglen != modulus_bytelen) {
      return CRYPT_INVALID_ARG;
   }

   /* should start with 0x00 0x02 */
   if (msg[0] != 0x00 || msg[1] != 0x02) {
      return CRYPT_OK;
   }
   
   /* skip over PS */
   x = 2 + (modulus_bytelen - outlen - 3);

   /* should be 0x00 */
   if (msg[x++] != 0x00) {
      return CRYPT_OK;
   }

   /* the message is left */
   if (x + outlen > modulus_bytelen) {
      return CRYPT_PK_INVALID_SIZE;
   }
   XMEMCPY(out, msg + x, outlen);
   *res = 1;
   return CRYPT_OK;
}

#endif 

