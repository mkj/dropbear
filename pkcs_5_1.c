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
   hash_state    *md;
   unsigned char *buf;

   _ARGCHK(password != NULL);
   _ARGCHK(salt     != NULL);
   _ARGCHK(out      != NULL);
   _ARGCHK(outlen   != NULL);

   /* test hash IDX */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }

   /* allocate memory */
   md  = XMALLOC(sizeof(hash_state));
   buf = XMALLOC(MAXBLOCKSIZE);
   if (md == NULL || buf == NULL) {
      if (md != NULL) {
         XFREE(md);
      }
      if (buf != NULL) { 
         XFREE(buf);
      }
      return CRYPT_MEM;
   }        

   /* hash initial password + salt */
   if ((err = hash_descriptor[hash_idx].init(md)) != CRYPT_OK) {
       goto __ERR;
   }
   if ((err = hash_descriptor[hash_idx].process(md, password, password_len)) != CRYPT_OK) {
       goto __ERR;
   }
   if ((err = hash_descriptor[hash_idx].process(md, salt, 8)) != CRYPT_OK) {
       goto __ERR;
   }
   if ((err = hash_descriptor[hash_idx].done(md, buf)) != CRYPT_OK) {
       goto __ERR;
   }

   while (--iteration_count) {
      // code goes here.
      x = MAXBLOCKSIZE;
      if ((err = hash_memory(hash_idx, buf, hash_descriptor[hash_idx].hashsize, buf, &x)) != CRYPT_OK) {
         goto __ERR;
      }
   }

   /* copy upto outlen bytes */
   for (x = 0; x < hash_descriptor[hash_idx].hashsize && x < *outlen; x++) {
       out[x] = buf[x];
   }
   *outlen = x;
   err = CRYPT_OK;
__ERR:
#ifdef CLEAN_STACK 
   zeromem(buf, MAXBLOCKSIZE);
   zeromem(md, sizeof(hash_state));
#endif

   XFREE(buf);
   XFREE(md);

   return err;
}

#endif
