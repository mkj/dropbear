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

/* PSS pad then sign */
int rsa_sign_hash(const unsigned char *msghash,  unsigned long  msghashlen, 
                        unsigned char *sig,      unsigned long *siglen, 
                        prng_state    *prng,     int            prng_idx,
                        int            hash_idx, unsigned long  saltlen,
                        rsa_key *key)
{
   unsigned long modulus_bitlen, modulus_bytelen, x;
   int           err;
   
  _ARGCHK(msghash  != NULL);
  _ARGCHK(sig      != NULL);
  _ARGCHK(siglen   != NULL);
  _ARGCHK(key      != NULL);
  
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
  if (modulus_bytelen > *siglen) {
     return CRYPT_BUFFER_OVERFLOW;
  }
      
  /* PSS pad the key */
  x = *siglen;
  if ((err = pkcs_1_pss_encode(msghash, msghashlen, saltlen, prng, prng_idx,
                               hash_idx, modulus_bitlen, sig, &x)) != CRYPT_OK) {
     return err;
  }

  /* RSA encode it */
  return rsa_exptmod(sig, x, sig, siglen, PK_PRIVATE, prng, prng_idx, key);
}

#endif /* MRSA */
