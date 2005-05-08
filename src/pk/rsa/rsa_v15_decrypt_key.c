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
  @file rsa_v15_decrypt_key.c
  RSA PKCS v1.5 Decryption, Tom St Denis
*/  

#ifdef MRSA

/**
   RSA decrypt then PKCS #1 v1.5 depad 
   @param in        The ciphertext
   @param inlen     The length of the ciphertext (octets)
   @param out       [out] The plaintext
   @param outlen    The length of the plaintext (you have to tell this function as it's not part of PKCS #1 v1.0 padding!)
   @param stat      [out] Status of decryption, 1==valid, 0==invalid
   @param key       The corresponding private RSA key
   @return CRYPT_OK if successful (even if invalid)   
*/
int rsa_v15_decrypt_key(const unsigned char *in,     unsigned long  inlen,
                              unsigned char *out,    unsigned long  outlen, 
                              int           *stat,   rsa_key       *key)
{
  unsigned long modulus_bitlen, modulus_bytelen, x;
  int           err;
  unsigned char *tmp;
  
  LTC_ARGCHK(out    != NULL);
  LTC_ARGCHK(key    != NULL);
  LTC_ARGCHK(stat   != NULL);
 
  /* default to invalid */
  *stat = 0;

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
  if ((err = rsa_exptmod(in, inlen, tmp, &x, PK_PRIVATE, key)) != CRYPT_OK) {
     XFREE(tmp);
     return err;
  }

  /* PKCS #1 v1.5 depad */
  err = pkcs_1_v15_es_decode(tmp, x, modulus_bitlen, out, outlen, stat);
  XFREE(tmp);
  return err;
}

#endif
