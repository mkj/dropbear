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

/* de-sign then PKCS v1.5 depad */
int rsa_v15_verify_hash(const unsigned char *sig,      unsigned long siglen,
                        const unsigned char *msghash,  unsigned long msghashlen,
                              prng_state    *prng,     int           prng_idx,
                              int            hash_idx, int          *stat,     
                              rsa_key       *key)
{
   unsigned long modulus_bitlen, modulus_bytelen, x;
   int           err;
   unsigned char *tmpbuf;
   
  _ARGCHK(msghash  != NULL);
  _ARGCHK(sig      != NULL);
  _ARGCHK(stat     != NULL);
  _ARGCHK(key      != NULL);

  /* default to invalid */
  *stat = 0;
  
  /* valid hash ? */
  if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
     return err;
  }

  if ((err = prng_is_valid(prng_idx)) != CRYPT_OK) {
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
  if ((err = rsa_exptmod(sig, siglen, tmpbuf, &x, PK_PUBLIC, prng, prng_idx, key)) != CRYPT_OK) {
     XFREE(tmpbuf);
     return err;
  }
  
  /* PSS decode it */
  err = pkcs_1_v15_sa_decode(msghash, msghashlen, tmpbuf, x, hash_idx, modulus_bitlen, stat);
  XFREE(tmpbuf);
  return err;
}

#endif
