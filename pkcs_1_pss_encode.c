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
                            unsigned long saltlen,  prng_state   *prng,     
                            int           prng_idx, int           hash_idx,
                            unsigned long modulus_bitlen,
                            unsigned char *out,     unsigned long *outlen)
{
   unsigned char *DB, *mask, *salt, *hash;
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

   /* allocate ram for DB/mask/salt/hash of size modulus_len */
   DB   = XMALLOC(modulus_len);
   mask = XMALLOC(modulus_len);
   salt = XMALLOC(modulus_len);
   hash = XMALLOC(modulus_len);
   if (DB == NULL || mask == NULL || salt == NULL || hash == NULL) {
      if (DB != NULL) {
         XFREE(DB);
      }
      if (mask != NULL) {
         XFREE(mask);
      }
      if (salt != NULL) {
         XFREE(salt);
      }
      if (hash != NULL) {
         XFREE(hash);
      }
      return CRYPT_MEM;
   }


   /* check sizes */
   if ((saltlen > modulus_len) || (modulus_len < hLen + saltlen + 2)) {
      err = CRYPT_INVALID_ARG;
      goto __ERR;
   }

   /* generate random salt */
   if (saltlen > 0) {
      if (prng_descriptor[prng_idx].read(salt, saltlen, prng) != saltlen) {
         err = CRYPT_ERROR_READPRNG;
         goto __ERR;
      }
   }

   /* M = (eight) 0x00 || msghash || salt, hash = H(M) */
   if ((err = hash_descriptor[hash_idx].init(&md)) != CRYPT_OK) {
      goto __ERR;
   }
   zeromem(DB, 8);
   if ((err = hash_descriptor[hash_idx].process(&md, DB, 8)) != CRYPT_OK) {
      goto __ERR;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, msghash, msghashlen)) != CRYPT_OK) {
      goto __ERR;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, salt, saltlen)) != CRYPT_OK) {
      goto __ERR;
   }
   if ((err = hash_descriptor[hash_idx].done(&md, hash)) != CRYPT_OK) {
      goto __ERR;
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
      goto __ERR;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLen - 1); y++) {
      DB[y] ^= mask[y];
   }

   /* output is DB || hash || 0xBC */
   if (*outlen < modulus_len) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto __ERR;
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
   out[0] &= 0xFF >> ((modulus_len<<3) - (modulus_bitlen-1));

   /* store output size */
   *outlen = modulus_len;
   err = CRYPT_OK;
__ERR:
#ifdef CLEAN_STACK
   zeromem(DB,   modulus_len);   
   zeromem(mask, modulus_len);   
   zeromem(salt, modulus_len);   
   zeromem(hash, modulus_len);   
#endif

   XFREE(hash);
   XFREE(salt);
   XFREE(mask);
   XFREE(DB);

   return err;
}

#endif /* PKCS_1 */
