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

/* OAEP Padding for PKCS #1 -- Tom St Denis */

#ifdef PKCS_1

int pkcs_1_oaep_encode(const unsigned char *msg,    unsigned long msglen,
                       const unsigned char *lparam, unsigned long lparamlen,
                             unsigned long modulus_bitlen, prng_state *prng,
                             int           prng_idx,         int  hash_idx,
                             unsigned char *out,    unsigned long *outlen)
{
   unsigned char *DB, *seed, *mask;
   unsigned long hLen, x, y, modulus_len;
   int           err;

   _ARGCHK(msg    != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

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

   /* test message size */
   if (msglen > (modulus_len - 2*hLen - 2)) {
      err = CRYPT_PK_INVALID_SIZE;
      goto __ERR;
   }

   /* get lhash */
   /* DB == lhash || PS || 0x01 || M, PS == k - mlen - 2hlen - 2 zeroes */
   x = modulus_len;
   if (lparam != NULL) {
      if ((err = hash_memory(hash_idx, lparam, lparamlen, DB, &x)) != CRYPT_OK) {
         goto __ERR;
      }
   } else {
      /* can't pass hash_memory a NULL so use DB with zero length */
      if ((err = hash_memory(hash_idx, DB, 0, DB, &x)) != CRYPT_OK) {
         goto __ERR;
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
      goto __ERR;
   }

   /* compute MGF1 of seed (k - hlen - 1) */
   if ((err = pkcs_1_mgf1(seed, hLen, hash_idx, mask, modulus_len - hLen - 1)) != CRYPT_OK) {
      goto __ERR;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLen - 1); y++) {
       DB[y] ^= mask[y]; 
   }

   /* compute MGF1 of maskedDB (hLen) */ 
   if ((err = pkcs_1_mgf1(DB, modulus_len - hLen - 1, hash_idx, mask, hLen)) != CRYPT_OK) {
      goto __ERR;
   }

   /* XOR against seed */
   for (y = 0; y < hLen; y++) {
      seed[y] ^= mask[y];
   }

   /* create string of length modulus_len */
   if (*outlen < modulus_len) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto __ERR;
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
__ERR:
#ifdef CLEAN_STACK
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

