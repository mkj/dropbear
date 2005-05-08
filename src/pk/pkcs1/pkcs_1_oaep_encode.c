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
  @file pkcs_1_oaep_encode.c
  OAEP Padding for PKCS #1, Tom St Denis 
*/

#ifdef PKCS_1

/**
  PKCS #1 v2.00 OAEP encode
  @param msg             The data to encode
  @param msglen          The length of the data to encode (octets)
  @param lparam          A session or system parameter (can be NULL)
  @param lparamlen       The length of the lparam data
  @param modulus_bitlen  The bit length of the RSA modulus
  @param prng            An active PRNG state
  @param prng_idx        The index of the PRNG desired
  @param hash_idx        The index of the hash desired
  @param out             [out] The destination for the encoded data
  @param outlen          [in/out] The max size and resulting size of the encoded data
  @return CRYPT_OK if successful
*/
int pkcs_1_oaep_encode(const unsigned char *msg,    unsigned long msglen,
                       const unsigned char *lparam, unsigned long lparamlen,
                             unsigned long modulus_bitlen, prng_state *prng,
                             int           prng_idx,         int  hash_idx,
                             unsigned char *out,    unsigned long *outlen)
{
   unsigned char *DB, *seed, *mask;
   unsigned long hLen, x, y, modulus_len;
   int           err;

   LTC_ARGCHK(msg    != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* test valid hash */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) { 
      return err;
   }

   /* valid prng */
   if ((err = prng_is_valid(prng_idx)) != CRYPT_OK) {
      return err;
   }

   hLen        = hash_descriptor[hash_idx].hashsize;
   modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

   /* test message size */
   if ((2*hLen >= (modulus_len - 2)) || (msglen > (modulus_len - 2*hLen - 2))) {
      return CRYPT_PK_INVALID_SIZE;
   }

   /* allocate ram for DB/mask/salt of size modulus_len */
   DB   = XMALLOC(modulus_len);
   mask = XMALLOC(modulus_len);
   seed = XMALLOC(modulus_len);
   if (DB == NULL || mask == NULL || seed == NULL) {
      if (DB != NULL) {
         XFREE(DB);
      }
      if (mask != NULL) {
         XFREE(mask);
      }
      if (seed != NULL) {
         XFREE(seed);
      }
      return CRYPT_MEM;
   }

   /* get lhash */
   /* DB == lhash || PS || 0x01 || M, PS == k - mlen - 2hlen - 2 zeroes */
   x = modulus_len;
   if (lparam != NULL) {
      if ((err = hash_memory(hash_idx, lparam, lparamlen, DB, &x)) != CRYPT_OK) {
         goto LBL_ERR;
      }
   } else {
      /* can't pass hash_memory a NULL so use DB with zero length */
      if ((err = hash_memory(hash_idx, DB, 0, DB, &x)) != CRYPT_OK) {
         goto LBL_ERR;
      }
   }

   /* append PS then 0x01 (to lhash)  */
   x = hLen;
   y = modulus_len - msglen - 2*hLen - 2;
   while (y--) {
      DB[x++] = 0x00;
   }
   DB[x++] = 0x01;

   /* message */
   y = msglen;
   while (y--) {
     DB[x++] = *msg++;
   }

   /* now choose a random seed */
   if (prng_descriptor[prng_idx].read(seed, hLen, prng) != hLen) {
      err = CRYPT_ERROR_READPRNG;
      goto LBL_ERR;
   }

   /* compute MGF1 of seed (k - hlen - 1) */
   if ((err = pkcs_1_mgf1(seed, hLen, hash_idx, mask, modulus_len - hLen - 1)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLen - 1); y++) {
       DB[y] ^= mask[y]; 
   }

   /* compute MGF1 of maskedDB (hLen) */ 
   if ((err = pkcs_1_mgf1(DB, modulus_len - hLen - 1, hash_idx, mask, hLen)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* XOR against seed */
   for (y = 0; y < hLen; y++) {
      seed[y] ^= mask[y];
   }

   /* create string of length modulus_len */
   if (*outlen < modulus_len) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   /* start output which is 0x00 || maskedSeed || maskedDB */
   x = 0;
   out[x++] = 0x00;
   for (y = 0; y < hLen; y++) {
      out[x++] = seed[y];
   }
   for (y = 0; y < modulus_len - hLen - 1; y++) {
      out[x++] = DB[y];
   }
   *outlen = x;
    
   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(DB,   modulus_len);
   zeromem(seed, modulus_len);
   zeromem(mask, modulus_len);
#endif

   XFREE(seed);
   XFREE(mask);
   XFREE(DB);

   return err;
}

#endif /* PKCS_1 */

