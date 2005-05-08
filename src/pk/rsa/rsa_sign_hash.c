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
  @file rsa_sign_hash.c
  RSA PKCS v2 PSS sign hash, Tom St Denis
*/  

#ifdef MRSA

/**
  (PKCS #1, v2.0) PSS pad then sign 
  @param in        The hash to sign
  @param inlen     The length of the hash to sign (octets)
  @param out       [out] The signature
  @param outlen    [in/out] The max size and resulting size of the signature 
  @param prng      An active PRNG state
  @param prng_idx  The index of the PRNG desired
  @param hash_idx  The index of the hash desired
  @param saltlen   The length of the salt desired (octets)
  @param key       The private RSA key to use
  @return CRYPT_OK if successful
*/
int rsa_sign_hash(const unsigned char *in,       unsigned long  inlen, 
                        unsigned char *out,      unsigned long *outlen, 
                        prng_state    *prng,     int            prng_idx,
                        int            hash_idx, unsigned long  saltlen,
                        rsa_key *key)
{
   unsigned long modulus_bitlen, modulus_bytelen, x;
   int           err;
   
  LTC_ARGCHK(in       != NULL);
  LTC_ARGCHK(out      != NULL);
  LTC_ARGCHK(outlen   != NULL);
  LTC_ARGCHK(key      != NULL);
  
  /* valid prng and hash ? */
  if ((err = prng_is_valid(prng_idx)) != CRYPT_OK) {
     return err;
  }
  if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
     return err;
  }
  
  /* get modulus len in bits */
  modulus_bitlen = mp_count_bits(&(key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = mp_unsigned_bin_size(&(key->N));
  if (modulus_bytelen > *outlen) {
     return CRYPT_BUFFER_OVERFLOW;
  }
      
  /* PSS pad the key */
  x = *outlen;
  if ((err = pkcs_1_pss_encode(in, inlen, saltlen, prng, prng_idx,
                               hash_idx, modulus_bitlen, out, &x)) != CRYPT_OK) {
     return err;
  }

  /* RSA encode it */
  return rsa_exptmod(out, x, out, outlen, PK_PRIVATE, key);
}

#endif /* MRSA */
