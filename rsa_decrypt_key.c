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

/* (PKCS #1 v2.0) decrypt then OAEP depad  */
int rsa_decrypt_key(const unsigned char *in,     unsigned long inlen,
                          unsigned char *outkey, unsigned long *keylen, 
                    const unsigned char *lparam, unsigned long lparamlen,
                          prng_state    *prng,   int           prng_idx,
                          int            hash_idx, int *res,
                          rsa_key       *key)
{
  unsigned long modulus_bitlen, modulus_bytelen, x;
  int           err;
  unsigned char *tmp;
  
  _ARGCHK(outkey != NULL);
  _ARGCHK(keylen != NULL);
  _ARGCHK(key    != NULL);
  _ARGCHK(res    != NULL);

  /* default to invalid */
  *res = 0;

  /* valid hash/prng ? */
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
  if (modulus_bytelen != inlen) {
     return CRYPT_INVALID_PACKET;
  }

  /* allocate ram */
  tmp = XMALLOC(inlen);
  if (tmp == NULL) {
     return CRYPT_MEM;
  }

  /* rsa decode the packet */
  x = inlen;
  if ((err = rsa_exptmod(in, inlen, tmp, &x, PK_PRIVATE, prng, prng_idx, key)) != CRYPT_OK) {
     XFREE(tmp);
     return err;
  }

  /* now OAEP decode the packet */
  err = pkcs_1_oaep_decode(tmp, x, lparam, lparamlen, modulus_bitlen, hash_idx,
                           outkey, keylen, res);
  XFREE(tmp);
  return err;
}

#endif /* MRSA */




