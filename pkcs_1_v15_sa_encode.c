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

/* PKCS #1 v1.5 Signature Padding -- Tom St Denis */

#ifdef PKCS_1

int pkcs_1_v15_sa_encode(const unsigned char *msghash,  unsigned long msghashlen,
                               int            hash_idx, unsigned long modulus_bitlen,
                               unsigned char *out,      unsigned long *outlen)
{
  unsigned long derlen, modulus_bytelen, x, y;
  int err;

  _ARGCHK(msghash != NULL)
  _ARGCHK(out     != NULL);
  _ARGCHK(outlen  != NULL);

  if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
     return err;
  }

  /* hack, to detect any hash without a DER OID */
  if (hash_descriptor[hash_idx].DERlen == 0) {
     return CRYPT_INVALID_ARG; 
  }

  /* get modulus len */
  modulus_bytelen = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

  /* get der len ok?  Forgive my lame German accent.... */
  derlen = hash_descriptor[hash_idx].DERlen;

  /* valid sizes? */
  if (msghashlen + 3 + derlen > modulus_bytelen) {
     return CRYPT_PK_INVALID_SIZE;
  }

  if (*outlen < modulus_bytelen) {
     return CRYPT_BUFFER_OVERFLOW;
  }

  /* packet is 0x00 0x01 PS 0x00 T, where PS == 0xFF repeated modulus_bytelen - 3 - derlen - msghashlen times, T == DER || hash */
  x = 0;
  out[x++] = 0x00;
  out[x++] = 0x01;
  for (y = 0; y < (modulus_bytelen - 3 - derlen - msghashlen); y++) {
     out[x++] = 0xFF;
  }
  out[x++] = 0x00;
  for (y = 0; y < derlen; y++) {
     out[x++] = hash_descriptor[hash_idx].DER[y];
  }
  for (y = 0; y < msghashlen; y++) {
     out[x++] = msghash[y];
  }

  *outlen = modulus_bytelen;
  return CRYPT_OK;
}

#endif /* PKCS_1 */
