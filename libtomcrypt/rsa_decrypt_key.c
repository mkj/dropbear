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

/* decrypt then OAEP depad  */
int rsa_decrypt_key(const unsigned char *in,     unsigned long inlen,
                          unsigned char *outkey, unsigned long *keylen, 
                    const unsigned char *lparam, unsigned long lparamlen,
                          prng_state    *prng,   int           prng_idx,
                          int            hash_idx, int *res,
                          rsa_key       *key)
{
  unsigned long modulus_bitlen, modulus_bytelen, x;
  int           err;
  
  _ARGCHK(outkey != NULL);
  _ARGCHK(keylen != NULL);
  _ARGCHK(key    != NULL);
  _ARGCHK(res    != NULL);
  
  /* valid hash ? */
  if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
     return err;
  }
  
  /* get modulus len in bits */
  modulus_bitlen = mp_count_bits(&(key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = mp_unsigned_bin_size(&(key->N));
  if (modulus_bytelen != inlen) {
     return CRYPT_INVALID_PACKET;
  }

  /* rsa decode the packet */
  x = *keylen;
  if ((err = rsa_exptmod(in, inlen, outkey, &x, PK_PRIVATE, prng, prng_idx, key)) != CRYPT_OK) {
     return err;
  }

  /* now OAEP decode the packet */
  return pkcs_1_oaep_decode(outkey, x, lparam, lparamlen, modulus_bitlen, hash_idx,
                            outkey, keylen, res);
}

#endif /* MRSA */




