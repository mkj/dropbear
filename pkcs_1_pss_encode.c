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

int pkcs_1_pss_encode(const unsigned char *msghash, unsigned long msghashlen,
                            unsigned long saltlen,  int           hash_idx,
                            int           prng_idx, prng_state   *prng,
                            unsigned long modulus_bitlen,
                            unsigned char *out,     unsigned long *outlen)
{
   unsigned char DB[1024], mask[sizeof(DB)], salt[sizeof(DB)], hash[sizeof(DB)];
   unsigned long x, y, hLen, modulus_len;
   int           err;
   hash_state    md;

   _ARGCHK(msghash != NULL);
   _ARGCHK(out     != NULL);
   _ARGCHK(outlen  != NULL);

   /* ensure hash and PRNG are valid */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }
   if ((err = prng_is_valid(prng_idx)) != CRYPT_OK) {
      return err;
   }

   hLen        = hash_descriptor[hash_idx].hashsize;
   modulus_len = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

   /* check sizes */
   if ((saltlen > sizeof(salt)) || (modulus_len > sizeof(DB)) || (modulus_len < hLen + saltlen + 2)) {
      return CRYPT_INVALID_ARG;
   }

   /* generate random salt */
   if (saltlen > 0) {
      if (prng_descriptor[prng_idx].read(salt, saltlen, prng) != saltlen) {
         return CRYPT_ERROR_READPRNG;
      }
   }

   /* M = (eight) 0x00 || msghash || salt, hash = H(M) */
   hash_descriptor[hash_idx].init(&md);
   zeromem(DB, 8);
   if ((err = hash_descriptor[hash_idx].process(&md, DB, 8)) != CRYPT_OK) {
      return err;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, msghash, msghashlen)) != CRYPT_OK) {
      return err;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, salt, saltlen)) != CRYPT_OK) {
      return err;
   }
   if ((err = hash_descriptor[hash_idx].done(&md, hash)) != CRYPT_OK) {
      return err;
   }

   /* generate DB = PS || 0x01 || salt, PS == modulus_len - saltlen - hLen - 2 zero bytes */
   for (x = 0; x < (modulus_len - saltlen - hLen - 2); x++) {
       DB[x] = 0x00;
   }
   DB[x++] = 0x01;
   for (y = 0; y < saltlen; y++) {
      DB[x++] = salt[y];
   }

   /* generate mask of length modulus_len - hLen - 1 from hash */
   if ((err = pkcs_1_mgf1(hash, hLen, hash_idx, mask, modulus_len - hLen - 1)) != CRYPT_OK) {
      return err;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLen - 1); y++) {
      DB[y] ^= mask[y];
   }

   /* output is DB || hash || 0xBC */
   if (*outlen < modulus_len) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* DB */
   for (y = x = 0; x < modulus_len - hLen - 1; x++) {
       out[y++] = DB[x];
   }
   /* hash */
   for (x = 0; x < hLen; x++) {
       out[y++] = hash[x];
   }
   /* 0xBC */
   out[y] = 0xBC;

   /* now clear the 8*modulus_len - modulus_bitlen most significant bits */
   out[0] &= 0xFF >> ((modulus_len<<3) - modulus_bitlen);

   /* store output size */
   *outlen = modulus_len;

#ifdef CLEAN_STACK
   zeromem(DB,   sizeof(DB));   
   zeromem(mask, sizeof(mask));   
   zeromem(salt, sizeof(salt));   
   zeromem(hash, sizeof(hash));   
#endif

   return CRYPT_OK;
}

#endif /* PKCS_1 */
