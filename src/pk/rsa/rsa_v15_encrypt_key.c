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
  @file rsa_v15_encrypt_key.c
  RSA PKCS v1.5 Encryption, Tom St Denis
*/  

#ifdef MRSA

/** 
   PKCS #1 v1.5 pad then encrypt
   @param in          The plaintext
   @param inlen       The length of the plaintext (octets)
   @param out         [out] The ciphertext
   @param outlen      [in/out] The max size and resulting size of the ciphertext 
   @param prng        An active PRNG
   @param prng_idx    The index of the desired PRNG
   @param key         The public RSA key
   @return CRYPT_OK if successful
*/   
int rsa_v15_encrypt_key(const unsigned char *in,    unsigned long  inlen,
                              unsigned char *out,   unsigned long *outlen,
                              prng_state    *prng,  int            prng_idx, 
                              rsa_key       *key)
{
  unsigned long modulus_bitlen, modulus_bytelen, x;
  int           err;
  
  LTC_ARGCHK(in     != NULL);
  LTC_ARGCHK(out    != NULL);
  LTC_ARGCHK(outlen != NULL);
  LTC_ARGCHK(key    != NULL);
  
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
  if ((err = pkcs_1_v15_es_encode(in, inlen, modulus_bitlen, prng, prng_idx, out, &x)) != CRYPT_OK) {
     return err;
  }
  
  /* encrypt it */
  return rsa_exptmod(out, x, out, outlen, PK_PUBLIC, key);
}

#endif
