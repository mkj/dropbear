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
   @file rsa_v15_sign_hash.c
   RSA PKCS v1.5 Signature, Tom St Denis
*/   

#ifdef MRSA

/** 
   PKCS #1 v1.5 pad then sign
   @param in             The hash to sign
   @param inlen          The length of the message hash (octets)
   @param out            [out] The signature
   @param siglen         [in/out] The max size and resulting size of the signature
   @param hash_idx       The index of the hash desired
   @param key            The private RSA key to perform the signature with
   @return CRYPT_OK if successful
*/
int rsa_v15_sign_hash(const unsigned char *in,       unsigned long  inlen, 
                            unsigned char *out,      unsigned long *siglen, 
                            int            hash_idx, rsa_key       *key)
{
   unsigned long modulus_bitlen, modulus_bytelen, x;
   int           err;
   
  LTC_ARGCHK(in  != NULL);
  LTC_ARGCHK(out      != NULL);
  LTC_ARGCHK(siglen   != NULL);
  LTC_ARGCHK(key      != NULL);
  
  /* valid hash ? */
  if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
     return err;
  }
  
  /* get modulus len in bits */
  modulus_bitlen = mp_count_bits(&(key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = mp_unsigned_bin_size(&(key->N));
  if (modulus_bytelen > *siglen) {
     return CRYPT_BUFFER_OVERFLOW;
  }
      
  /* PKCS #1 v1.5 pad the key */
  x = *siglen;
  if ((err = pkcs_1_v15_sa_encode(in, inlen, hash_idx, modulus_bitlen, out, &x)) != CRYPT_OK) {
     return err;
  }

  /* RSA encode it */
  return rsa_exptmod(out, x, out, siglen, PK_PRIVATE, key);
}

#endif
