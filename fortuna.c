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

/* Implementation of Fortuna by Tom St Denis 

We deviate slightly here for reasons of simplicity [and to fit in the API].  First all "sources"
in the AddEntropy function are fixed to 0.  Second since no reliable timer is provided 
we reseed automatically when len(pool0) >= 64 or every FORTUNA_WD calls to the read function */

#include "mycrypt.h"

#ifdef FORTUNA 

/* requries SHA256 and AES  */
#if !(defined(RIJNDAEL) && defined(SHA256))
   #error FORTUNA requires SHA256 and RIJNDAEL (AES)
#endif

#ifndef FORTUNA_POOLS
   #warning FORTUNA_POOLS was not previously defined (old headers?)
   #define FORTUNA_POOLS 32
#endif

#if FORTUNA_POOLS < 4 || FORTUNA_POOLS > 32
   #error FORTUNA_POOLS must be in [4..32]
#endif

const struct _prng_descriptor fortuna_desc = {
    "fortuna", 1024,
    &fortuna_start,
    &fortuna_add_entropy,
    &fortuna_ready,
    &fortuna_read,
    &fortuna_done,
    &fortuna_export,
    &fortuna_import,
    &fortuna_test
};

/* update the IV */
static void fortuna_update_iv(prng_state *prng)
{
   int            x;
   unsigned char *IV;
   /* update IV */
   IV = prng->fortuna.IV;
   for (x = 0; x < 16; x++) {
      IV[x] = (IV[x] + 1) & 255;
      if (IV[x] != 0) break;
   }
}

/* reseed the PRNG */
static int fortuna_reseed(prng_state *prng)
{
   unsigned char tmp[MAXBLOCKSIZE];
   hash_state    md;
   int           err, x;

   ++prng->fortuna.reset_cnt;

   /* new K == SHA256(K || s) where s == SHA256(P0) || SHA256(P1) ... */
   sha256_init(&md);
   if ((err = sha256_process(&md, prng->fortuna.K, 32)) != CRYPT_OK) {
      return err;
   }

   for (x = 0; x < FORTUNA_POOLS; x++) {
       if (x == 0 || ((prng->fortuna.reset_cnt >> (x-1)) & 1) == 0) { 
          /* terminate this hash */
          if ((err = sha256_done(&prng->fortuna.pool[x], tmp)) != CRYPT_OK) {
             return err; 
          }
          /* add it to the string */
          if ((err = sha256_process(&md, tmp, 32)) != CRYPT_OK) {
             return err;
          }
          /* reset this pool */
          sha256_init(&prng->fortuna.pool[x]);
       } else {
          break;
       }
   }

   /* finish key */
   if ((err = sha256_done(&md, prng->fortuna.K)) != CRYPT_OK) {
      return err; 
   }
   if ((err = rijndael_setup(prng->fortuna.K, 32, 0, &prng->fortuna.skey)) != CRYPT_OK) {
      return err;
   }
   fortuna_update_iv(prng);

   /* reset pool len */
   prng->fortuna.pool0_len = 0;
   prng->fortuna.wd        = 0;


#ifdef CLEAN_STACK
   zeromem(&md, sizeof(md));
   zeromem(tmp, sizeof(tmp));
#endif

   return CRYPT_OK;
}

int fortuna_start(prng_state *prng)
{
   int err, x;

   _ARGCHK(prng != NULL);
   
   /* initialize the pools */
   for (x = 0; x < FORTUNA_POOLS; x++) {
       sha256_init(&prng->fortuna.pool[x]);
   }
   prng->fortuna.pool_idx = prng->fortuna.pool0_len = prng->fortuna.reset_cnt = 
   prng->fortuna.wd = 0;

   /* reset bufs */
   zeromem(prng->fortuna.K, 32);
   if ((err = rijndael_setup(prng->fortuna.K, 32, 0, &prng->fortuna.skey)) != CRYPT_OK) {
      return err;
   }
   zeromem(prng->fortuna.IV, 16);

   return CRYPT_OK;
}

int fortuna_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng)
{
   unsigned char tmp[2];
   int           err;

   _ARGCHK(buf  != NULL);
   _ARGCHK(prng != NULL);

   /* ensure len <= 32 */
   if (len > 32) {
      return CRYPT_INVALID_ARG;
   }

   /* add s || length(buf) || buf to pool[pool_idx] */
   tmp[0] = 0;
   tmp[1] = len;
   if ((err = sha256_process(&prng->fortuna.pool[prng->fortuna.pool_idx], tmp, 2)) != CRYPT_OK) {
      return err;
   }
   if ((err = sha256_process(&prng->fortuna.pool[prng->fortuna.pool_idx], buf, len)) != CRYPT_OK) {
      return err;
   }
   if (prng->fortuna.pool_idx == 0) {
      prng->fortuna.pool0_len += len;
   }
   if (++(prng->fortuna.pool_idx) == FORTUNA_POOLS) {
      prng->fortuna.pool_idx = 0;
   }

   return CRYPT_OK;
}

int fortuna_ready(prng_state *prng)
{
   return fortuna_reseed(prng);
}

unsigned long fortuna_read(unsigned char *dst, unsigned long len, prng_state *prng)
{
   unsigned char tmp[16];
   int           err;
   unsigned long tlen;

   _ARGCHK(dst  != NULL);
   _ARGCHK(prng != NULL);

   /* do we have to reseed? */
   if (++prng->fortuna.wd == FORTUNA_WD || prng->fortuna.pool0_len >= 64) {
      if ((err = fortuna_reseed(prng)) != CRYPT_OK) {
         return 0;
      }
   }

   /* now generate the blocks required */
   tlen = len;

   /* handle whole blocks without the extra memcpy */
   while (len >= 16) {
      /* encrypt the IV and store it */
      rijndael_ecb_encrypt(prng->fortuna.IV, dst, &prng->fortuna.skey);
      dst += 16;
      len -= 16;
      fortuna_update_iv(prng);
   }

   /* left over bytes? */
   if (len > 0) {
      rijndael_ecb_encrypt(prng->fortuna.IV, tmp, &prng->fortuna.skey);
      XMEMCPY(dst, tmp, len);
      fortuna_update_iv(prng);
   }
       
   /* generate new key */
   rijndael_ecb_encrypt(prng->fortuna.IV, prng->fortuna.K   , &prng->fortuna.skey); fortuna_update_iv(prng);
   rijndael_ecb_encrypt(prng->fortuna.IV, prng->fortuna.K+16, &prng->fortuna.skey); fortuna_update_iv(prng);
   if ((err = rijndael_setup(prng->fortuna.K, 32, 0, &prng->fortuna.skey)) != CRYPT_OK) {
      return 0;
   }

#ifdef CLEAN_STACK
   zeromem(tmp, sizeof(tmp));
#endif
   return tlen;
}   

int fortuna_done(prng_state *prng)
{
   int           err, x;
   unsigned char tmp[32];

   _ARGCHK(prng != NULL);

   /* terminate all the hashes */
   for (x = 0; x < FORTUNA_POOLS; x++) {
       if ((err = sha256_done(&(prng->fortuna.pool[x]), tmp)) != CRYPT_OK) {
          return err; 
       }
   }
   /* call cipher done when we invent one ;-) */

#ifdef CLEAN_STACK
   zeromem(tmp, sizeof(tmp));
#endif

   return CRYPT_OK;
}

int fortuna_export(unsigned char *out, unsigned long *outlen, prng_state *prng)
{
   int         x, err;
   hash_state *md;

   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(prng   != NULL);

   /* we'll write bytes for s&g's */
   if (*outlen < 32*FORTUNA_POOLS) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   md = XMALLOC(sizeof(hash_state));
   if (md == NULL) {
      return CRYPT_MEM;
   }

   /* to emit the state we copy each pool, terminate it then hash it again so 
    * an attacker who sees the state can't determine the current state of the PRNG 
    */   
   for (x = 0; x < FORTUNA_POOLS; x++) {
      /* copy the PRNG */
      XMEMCPY(md, &(prng->fortuna.pool[x]), sizeof(*md));

      /* terminate it */
      if ((err = sha256_done(md, out+x*32)) != CRYPT_OK) {
         goto __ERR;
      }

      /* now hash it */
      if ((err = sha256_init(md)) != CRYPT_OK) {
         goto __ERR;
      }
      if ((err = sha256_process(md, out+x*32, 32)) != CRYPT_OK) {
         goto __ERR;
      }
      if ((err = sha256_done(md, out+x*32)) != CRYPT_OK) {
         goto __ERR;
      }
   }
   *outlen = 32*FORTUNA_POOLS;
   err = CRYPT_OK;

__ERR:
#ifdef CLEAN_STACK
   zeromem(md, sizeof(*md));
#endif
   XFREE(md);
   return err;
}
 
int fortuna_import(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   int err, x;

   _ARGCHK(in   != NULL);
   _ARGCHK(prng != NULL);

   if (inlen != 32*FORTUNA_POOLS) {
      return CRYPT_INVALID_ARG;
   }

   if ((err = fortuna_start(prng)) != CRYPT_OK) {
      return err;
   }
   for (x = 0; x < FORTUNA_POOLS; x++) {
      if ((err = fortuna_add_entropy(in+x*32, 32, prng)) != CRYPT_OK) {
         return err;
      }
   }
   return err;
}

int fortuna_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   int err;

   if ((err = sha256_test()) != CRYPT_OK) {
      return err;
   }
   return rijndael_test();
#endif
}

#endif

