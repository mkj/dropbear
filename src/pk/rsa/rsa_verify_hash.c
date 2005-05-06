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
  @file rsa_verify_hash.c
  RSA PKCS v2 PSS signature verification, Tom St Denis
*/  

#ifdef MRSA

/**
  (PKCS #1, v2.0) de-sign then PSS depad
  @param sig              The signature data
  @param siglen           The length of the signature data (octets)
  @param hash             The hash of the message that was signed
  @param hashlen          The length of the hash of the message that was signed (octets)
  @param hash_idx         The index of the desired hash
  @param saltlen          The length of the salt used during signature
  @param stat             [out] The result of the signature comparison, 1==valid, 0==invalid
  @param key              The public RSA key corresponding to the key that performed the signature
  @return CRYPT_OK on success (even if the signature is invalid)
*/
int rsa_verify_hash(const unsigned char *sig,      unsigned long siglen,
                    const unsigned char *hash,     unsigned long hashlen,
                          int            hash_idx, unsigned long saltlen,
                          int           *stat,     rsa_key      *key)
{
   unsigned long modulus_bitlen, modulus_bytelen, x;
   int           err;
   unsigned char *tmpbuf;
   
  LTC_ARGCHK(hash  != NULL);
  LTC_ARGCHK(sig      != NULL);
  LTC_ARGCHK(stat     != NULL);
  LTC_ARGCHK(key      != NULL);

  /* default to invalid */
  *stat = 0;
  
  /* valid hash ? */
  if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
     return err;
  }
  
  /* get modulus len in bits */
  modulus_bitlen = mp_count_bits(&(key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = mp_unsigned_bin_size(&(key->N));
  if (modulus_bytelen != siglen) {
     return CRYPT_INVALID_PACKET;
  }
  
  /* allocate temp buffer for decoded sig */
  tmpbuf = XMALLOC(siglen);
  if (tmpbuf == NULL) {
     return CRYPT_MEM;
  }
      
  /* RSA decode it  */
  x = siglen;
  if ((err = rsa_exptmod(sig, siglen, tmpbuf, &x, PK_PUBLIC, key)) != CRYPT_OK) {
     XFREE(tmpbuf);
     return err;
  }
  
  /* PSS decode it */
  err = pkcs_1_pss_decode(hash, hashlen, tmpbuf, x, saltlen, hash_idx, modulus_bitlen, stat);
  XFREE(tmpbuf);
  return err;
}

#endif /* MRSA */
