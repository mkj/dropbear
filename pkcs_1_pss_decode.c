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

/* PKCS #1 PSS Signature Padding -- Tom St Denis */

#ifdef PKCS_1

int pkcs_1_pss_decode(const unsigned char *msghash, unsigned long msghashlen,
                      const unsigned char *sig,     unsigned long siglen,
                            unsigned long saltlen,  int           hash_idx,
                            unsigned long modulus_bitlen, int    *res)
{
   unsigned char DB[1024], mask[sizeof(DB)], salt[sizeof(DB)], hash[sizeof(DB)];
   unsigned long x, y, hLen, modulus_len;
   int           err;
   hash_state    md;

   _ARGCHK(msghash != NULL);
   _ARGCHK(res     != NULL);

   /* default to invalid */
   *res = 0;

   /* ensure hash is valid */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }

   hLen        = hash_descriptor[hash_idx].hashsize;
   modulus_len = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

   /* check sizes */
   if ((saltlen > sizeof(salt)) || (modulus_len > sizeof(DB)) || 
       (modulus_len < hLen + saltlen + 2) || (siglen != modulus_len)) {
      return CRYPT_INVALID_ARG;
   }

   /* ensure the 0xBC byte */
   if (sig[siglen-1] != 0xBC) {
      return CRYPT_OK;
   }

   /* copy out the DB */
   for (x = 0; x < modulus_len - hLen - 1; x++) {
      DB[x] = sig[x];
   }

   /* copy out the hash */
   for (y = 0; y < hLen; y++) {
      hash[y] = sig[x++];
   }

   /* check the MSB */
   if ((sig[0] & ~(0xFF >> ((modulus_len<<3) - modulus_bitlen))) != 0) {
      return CRYPT_OK;
   }

   /* generate mask of length modulus_len - hLen - 1 from hash */
   if ((err = pkcs_1_mgf1(hash, hLen, hash_idx, mask, modulus_len - hLen - 1)) != CRYPT_OK) {
      return err;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLen - 1); y++) {
      DB[y] ^= mask[y];
   }

   /* DB = PS || 0x01 || salt, PS == modulus_len - saltlen - hLen - 2 zero bytes */

   /* check for zeroes and 0x01 */
   for (x = 0; x < modulus_len - saltlen - hLen - 2; x++) {
       if (DB[x] != 0x00) {
          return CRYPT_OK;
       }
   }

   if (DB[x++] != 0x01) {
      return CRYPT_OK;
   }

   /* M = (eight) 0x00 || msghash || salt, mask = H(M) */
   hash_descriptor[hash_idx].init(&md);
   zeromem(mask, 8);
   if ((err = hash_descriptor[hash_idx].process(&md, mask, 8)) != CRYPT_OK) {
      return err;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, msghash, msghashlen)) != CRYPT_OK) {
      return err;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, DB+x, saltlen)) != CRYPT_OK) {
      return err;
   }
   if ((err = hash_descriptor[hash_idx].done(&md, mask)) != CRYPT_OK) {
      return err;
   }

   /* mask == hash means valid signature */
   if (memcmp(mask, hash, hLen) == 0) {
      *res = 1;
   }

#ifdef CLEAN_STACK
   zeromem(DB,   sizeof(DB));   
   zeromem(mask, sizeof(mask));   
   zeromem(salt, sizeof(salt));   
   zeromem(hash, sizeof(hash));   
#endif

   return CRYPT_OK;
}

#endif /* PKCS_1 */
