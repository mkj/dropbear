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

#ifdef YARROW

const struct _prng_descriptor yarrow_desc =
{
    "yarrow", 64,
    &yarrow_start,
    &yarrow_add_entropy,
    &yarrow_ready,
    &yarrow_read,
    &yarrow_done,
    &yarrow_export,
    &yarrow_import,
    &yarrow_test
};

int yarrow_start(prng_state *prng)
{
   int err;
   
   _ARGCHK(prng != NULL);

   /* these are the default hash/cipher combo used */
#ifdef RIJNDAEL
#if    YARROW_AES==0
   prng->yarrow.cipher = register_cipher(&rijndael_enc_desc);
#elif  YARROW_AES==1
   prng->yarrow.cipher = register_cipher(&aes_enc_desc);
#elif  YARROW_AES==2
   prng->yarrow.cipher = register_cipher(&rijndael_desc);
#elif  YARROW_AES==3
   prng->yarrow.cipher = register_cipher(&aes_desc);
#endif
#elif defined(BLOWFISH)
   prng->yarrow.cipher = register_cipher(&blowfish_desc);
#elif defined(TWOFISH)
   prng->yarrow.cipher = register_cipher(&twofish_desc);
#elif defined(RC6)
   prng->yarrow.cipher = register_cipher(&rc6_desc);
#elif defined(RC5)
   prng->yarrow.cipher = register_cipher(&rc5_desc);
#elif defined(SAFERP)
   prng->yarrow.cipher = register_cipher(&saferp_desc);
#elif defined(RC2)
   prng->yarrow.cipher = register_cipher(&rc2_desc);
#elif defined(NOEKEON)   
   prng->yarrow.cipher = register_cipher(&noekeon_desc);
#elif defined(CAST5)
   prng->yarrow.cipher = register_cipher(&cast5_desc);
#elif defined(XTEA)
   prng->yarrow.cipher = register_cipher(&xtea_desc);
#elif defined(SAFER)
   prng->yarrow.cipher = register_cipher(&safer_sk128_desc);
#elif defined(DES)
   prng->yarrow.cipher = register_cipher(&des3_desc);
#else
   #error YARROW needs at least one CIPHER
#endif
   if ((err = cipher_is_valid(prng->yarrow.cipher)) != CRYPT_OK) {
      return err;
   }

#ifdef SHA256
   prng->yarrow.hash   = register_hash(&sha256_desc);
#elif defined(SHA512)
   prng->yarrow.hash   = register_hash(&sha512_desc);
#elif defined(TIGER)
   prng->yarrow.hash   = register_hash(&tiger_desc);
#elif defined(SHA1)
   prng->yarrow.hash   = register_hash(&sha1_desc);
#elif defined(RIPEMD160)
   prng->yarrow.hash   = register_hash(&rmd160_desc);
#elif defined(RIPEMD128)
   prng->yarrow.hash   = register_hash(&rmd128_desc);
#elif defined(MD5)
   prng->yarrow.hash   = register_hash(&md5_desc);
#elif defined(MD4)
   prng->yarrow.hash   = register_hash(&md4_desc);
#elif defined(MD2)
   prng->yarrow.hash   = register_hash(&md2_desc);
#elif defined(WHIRLPOOL)
   prng->yarrow.hash   = register_hash(&whirlpool_desc);
#else
   #error YARROW needs at least one HASH
#endif
   if ((err = hash_is_valid(prng->yarrow.hash)) != CRYPT_OK) {
      return err;
   }

   /* zero the memory used */
   zeromem(prng->yarrow.pool, sizeof(prng->yarrow.pool));

   return CRYPT_OK;
}

int yarrow_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng)
{
   hash_state md;
   int err;

   _ARGCHK(buf  != NULL);
   _ARGCHK(prng != NULL);

   if ((err = hash_is_valid(prng->yarrow.hash)) != CRYPT_OK) {
      return err;
   }

   /* start the hash */
   if ((err = hash_descriptor[prng->yarrow.hash].init(&md)) != CRYPT_OK) {
      return err; 
   }

   /* hash the current pool */
   if ((err = hash_descriptor[prng->yarrow.hash].process(&md, prng->yarrow.pool, 
                                                        hash_descriptor[prng->yarrow.hash].hashsize)) != CRYPT_OK) {
      return err;
   }

   /* add the new entropy */
   if ((err = hash_descriptor[prng->yarrow.hash].process(&md, buf, len)) != CRYPT_OK) {
      return err;
   }

   /* store result */
   if ((err = hash_descriptor[prng->yarrow.hash].done(&md, prng->yarrow.pool)) != CRYPT_OK) {
      return err;
   }

   return CRYPT_OK;
}

int yarrow_ready(prng_state *prng)
{
   int ks, err;

   _ARGCHK(prng != NULL);

   if ((err = hash_is_valid(prng->yarrow.hash)) != CRYPT_OK) {
      return err;
   }
   
   if ((err = cipher_is_valid(prng->yarrow.cipher)) != CRYPT_OK) {
      return err;
   }

   /* setup CTR mode using the "pool" as the key */
   ks = (int)hash_descriptor[prng->yarrow.hash].hashsize;
   if ((err = cipher_descriptor[prng->yarrow.cipher].keysize(&ks)) != CRYPT_OK) {
      return err;
   }

   if ((err = ctr_start(prng->yarrow.cipher,     /* what cipher to use */
                        prng->yarrow.pool,       /* IV */
                        prng->yarrow.pool, ks,   /* KEY and key size */
                        0,                       /* number of rounds */
                        &prng->yarrow.ctr)) != CRYPT_OK) {
      return err;
   }
   return CRYPT_OK;
}

unsigned long yarrow_read(unsigned char *buf, unsigned long len, prng_state *prng)
{
   _ARGCHK(buf  != NULL);
   _ARGCHK(prng != NULL);

   /* put buf in predictable state first */
   zeromem(buf, len);
   
   /* now randomize it */
   if (ctr_encrypt(buf, buf, len, &prng->yarrow.ctr) != CRYPT_OK) {
      return 0;
   }
   return len;
}

int yarrow_done(prng_state *prng)
{
   _ARGCHK(prng != NULL);
   /* call cipher done when we invent one ;-) */

   return CRYPT_OK;
}

int yarrow_export(unsigned char *out, unsigned long *outlen, prng_state *prng)
{
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(prng   != NULL);

   /* we'll write 64 bytes for s&g's */
   if (*outlen < 64) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (yarrow_read(out, 64, prng) != 64) {
      return CRYPT_ERROR_READPRNG;
   }
   *outlen = 64;

   return CRYPT_OK;
}
 
int yarrow_import(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   int err;

   _ARGCHK(in   != NULL);
   _ARGCHK(prng != NULL);

   if (inlen != 64) {
      return CRYPT_INVALID_ARG;
   }

   if ((err = yarrow_start(prng)) != CRYPT_OK) {
      return err;
   }
   return yarrow_add_entropy(in, 64, prng);
}

int yarrow_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   int err;
   prng_state prng;

   if ((err = yarrow_start(&prng)) != CRYPT_OK) {
      return err;
   }
   
   /* now let's test the hash/cipher that was chosen */
   if ((err = cipher_descriptor[prng.yarrow.cipher].test()) != CRYPT_OK) {
      return err; 
   }
   if ((err = hash_descriptor[prng.yarrow.hash].test()) != CRYPT_OK) {
      return err; 
   }

   yarrow_done(&prng);
   return CRYPT_OK;
#endif
}

#endif

