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

/* PKCS #1 v1.5 pad then encrypt */
int rsa_v15_encrypt_key(const unsigned char *inkey,    unsigned long  inlen,
                              unsigned char *outkey,   unsigned long *outlen,
                              prng_state    *prng,     int            prng_idx, 
                              rsa_key       *key)
{
  unsigned long modulus_bitlen, modulus_bytelen, x;
  int           err;
  
  _ARGCHK(inkey  != NULL);
  _ARGCHK(outkey != NULL);
  _ARGCHK(outlen != NULL);
  _ARGCHK(key    != NULL);
  
  /* valid prng? */
  if ((err = prng_is_valid(prng_idx)) != CRYPT_OK) {
     return err;
  }
  
  /* get modulus len in bits */
  modulus_bitlen = mp_count_bits(&(key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = mp_unsigned_bin_size(&(key->N));
  if (modulus_bytelen > *outlen) {
     return CRYPT_BUFFER_OVERFLOW;
  }
  
  /* pad it */
  x = *outlen;
  if ((err = pkcs_1_v15_es_encode(inkey, inlen, modulus_bitlen, prng, prng_idx, outkey, &x)) != CRYPT_OK) {
     return err;
  }
  
  /* encrypt it */
  return rsa_exptmod(outkey, x, outkey, outlen, PK_PUBLIC, prng, prng_idx, key);
}

#endif
