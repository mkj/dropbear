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
#include <mycrypt.h>

/* PKCS #5, Algorithm #1 */
#ifdef PKCS_5

int pkcs_5_alg1(const unsigned char *password, unsigned long password_len, 
                const unsigned char *salt, 
                int iteration_count,  int hash_idx,
                unsigned char *out,   unsigned long *outlen)
{
   int err;
   unsigned long x;
   hash_state md;
   unsigned char buf[MAXBLOCKSIZE];

   _ARGCHK(password != NULL);
   _ARGCHK(salt     != NULL);
   _ARGCHK(out      != NULL);
   _ARGCHK(outlen   != NULL);

   /* test hash IDX */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }

   /* hash initial password + salt */
   hash_descriptor[hash_idx].init(&md);
   hash_descriptor[hash_idx].process(&md, password, password_len);
   hash_descriptor[hash_idx].process(&md, salt, 8);
   hash_descriptor[hash_idx].done(&md, buf);

   while (--iteration_count) {
      // code goes here.
      x = sizeof(buf);
      if ((err = hash_memory(hash_idx, buf, hash_descriptor[hash_idx].hashsize, buf, &x)) != CRYPT_OK) {
         return err;
      }
   }

   /* copy upto outlen bytes */
   for (x = 0; x < hash_descriptor[hash_idx].hashsize && x < *outlen; x++) {
       out[x] = buf[x];
   }
   *outlen = x;

#ifdef CLEAN_STACK 
   zeromem(buf, sizeof(buf));
#endif

   return CRYPT_OK;
}

#endif
