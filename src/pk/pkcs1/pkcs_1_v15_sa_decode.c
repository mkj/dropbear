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
  @file pkcs_1_v15_sa_decode.c
  PKCS #1 v1.5 Signature Padding, Tom St Denis 
*/

#ifdef PKCS_1

/**
  Perform PKCS #1 v1.5 Signature Decoding
  @param msghash         The hash that was signed
  @param msghashlen      The length of the hash
  @param sig             The signature [padded data]
  @param siglen          The length of the signature
  @param hash_idx        The index of the hash used
  @param modulus_bitlen  The bit length of the RSA modulus 
  @param res             [out]  Result of comparison, 1==valid, 0==invalid
  @return CRYPT_OK if successful
*/
int pkcs_1_v15_sa_decode(const unsigned char *msghash, unsigned long msghashlen,
                         const unsigned char *sig,     unsigned long siglen,
                               int           hash_idx, unsigned long modulus_bitlen, 
                               int          *res)
{
   unsigned long x, y, modulus_bytelen, derlen;
   int err;
   
   LTC_ARGCHK(msghash != NULL);
   LTC_ARGCHK(sig     != NULL);
   LTC_ARGCHK(res     != NULL);

   /* default to invalid */
   *res = 0;

   /* valid hash ? */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }

   /* get derlen */
   derlen = hash_descriptor[hash_idx].DERlen;

   /* get modulus len */
   modulus_bytelen = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

   /* valid sizes? */
   if ((msghashlen + 3 + derlen > modulus_bytelen) || (siglen != modulus_bytelen)) {
      return CRYPT_PK_INVALID_SIZE;
   }

   /* packet is 0x00 0x01 PS 0x00 T, where PS == 0xFF repeated modulus_bytelen - 3 - derlen - msghashlen times, T == DER || hash */
   x = 0;
   if (sig[x++] != 0x00 || sig[x++] != 0x01) {
      return CRYPT_OK;
   }

   /* now follows (modulus_bytelen - 3 - derlen - msghashlen) 0xFF bytes */
   for (y = 0; y < (modulus_bytelen - 3 - derlen - msghashlen); y++) {
     if (sig[x++] != 0xFF) {
        return CRYPT_OK;
     }
   }

   if (sig[x++] != 0x00) {
      return CRYPT_OK;
   }

   for (y = 0; y < derlen; y++) {
      if (sig[x++] != hash_descriptor[hash_idx].DER[y]) {
         return CRYPT_OK;
      }
   }

   if (memcmp(msghash, sig+x, msghashlen) == 0) {
      *res = 1;
   }
   return CRYPT_OK;
}

#endif 
