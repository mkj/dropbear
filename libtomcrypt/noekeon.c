/* Implementation of the Noekeon block cipher by Tom St Denis */
#include "mycrypt.h"

#ifdef NOEKEON

const struct _cipher_descriptor noekeon_desc =
{
    "noekeon",
    16,
    16, 16, 16, 16,
    &noekeon_setup,
    &noekeon_ecb_encrypt,
    &noekeon_ecb_decrypt,
    &noekeon_test,
    &noekeon_keysize
};

static const ulong32 RC[] = {
   0x00000080UL, 0x0000001bUL, 0x00000036UL, 0x0000006cUL,
   0x000000d8UL, 0x000000abUL, 0x0000004dUL, 0x0000009aUL,
   0x0000002fUL, 0x0000005eUL, 0x000000bcUL, 0x00000063UL,
   0x000000c6UL, 0x00000097UL, 0x00000035UL, 0x0000006aUL,
   0x000000d4UL 
};


#define kTHETA(a, b, c, d)                                 \
    temp = a^c; temp = temp ^ ROL(temp, 8) ^ ROR(temp, 8); \
    b ^= temp; d ^= temp;                                  \
    temp = b^d; temp = temp ^ ROL(temp, 8) ^ ROR(temp, 8); \
    a ^= temp; c ^= temp;

#define THETA(k, a, b, c, d)                               \
    temp = a^c; temp = temp ^ ROL(temp, 8) ^ ROR(temp, 8); \
    b ^= temp ^ k[1]; d ^= temp ^ k[3];                    \
    temp = b^d; temp = temp ^ ROL(temp, 8) ^ ROR(temp, 8); \
    a ^= temp ^ k[0]; c ^= temp ^ k[2];
    
#define GAMMA(a, b, c, d)     \
    b ^= ~(d|c);              \
    a ^= c&b;                 \
    temp = d; d = a; a = temp;\
    c ^= a ^ b ^ d;           \
    b ^= ~(d|c);              \
    a ^= c&b;
    
#define PI1(a, b, c, d) \
    a = ROL(a, 1); c = ROL(c, 5); d = ROL(d, 2);
    
#define PI2(a, b, c, d) \
    a = ROR(a, 1); c = ROR(c, 5); d = ROR(d, 2);
    
int noekeon_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   ulong32 temp;
   
   _ARGCHK(key != NULL);
   _ARGCHK(skey != NULL);
   
   if (keylen != 16) {
      return CRYPT_INVALID_KEYSIZE;
   }
   
   if (num_rounds != 16 && num_rounds != 0) {
      return CRYPT_INVALID_ROUNDS;
   }
   
   LOAD32L(skey->noekeon.K[0],&key[0]);
   LOAD32L(skey->noekeon.K[1],&key[4]);
   LOAD32L(skey->noekeon.K[2],&key[8]);
   LOAD32L(skey->noekeon.K[3],&key[12]);
   
   LOAD32L(skey->noekeon.dK[0],&key[0]);
   LOAD32L(skey->noekeon.dK[1],&key[4]);
   LOAD32L(skey->noekeon.dK[2],&key[8]);
   LOAD32L(skey->noekeon.dK[3],&key[12]);

   kTHETA(skey->noekeon.dK[0], skey->noekeon.dK[1], skey->noekeon.dK[2], skey->noekeon.dK[3]);

   return CRYPT_OK;
}

#ifdef CLEAN_STACK
static void _noekeon_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key)
#else
void noekeon_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key)
#endif
{
   ulong32 a,b,c,d,temp;
#ifdef SMALL_CODE
   int r;
#endif

   _ARGCHK(key != NULL);
   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);
   
   LOAD32L(a,&pt[0]); LOAD32L(b,&pt[4]);
   LOAD32L(c,&pt[8]); LOAD32L(d,&pt[12]);
   

#ifdef SMALL_CODE
#define ROUND \
       a ^= RC[r]; \
       THETA(key->noekeon.K, a,b,c,d); \
       PI1(a,b,c,d); \
       GAMMA(a,b,c,d); \
       PI2(a,b,c,d);

   for (r = 0; r < 16; ++r) {
       ROUND;
   }
#else 

#define ROUND(i) \
       a ^= RC[i]; \
       THETA(key->noekeon.K, a,b,c,d); \
       PI1(a,b,c,d); \
       GAMMA(a,b,c,d); \
       PI2(a,b,c,d);

   ROUND( 0); ROUND( 1); ROUND( 2); ROUND( 3);
   ROUND( 4); ROUND( 5); ROUND( 6); ROUND( 7);
   ROUND( 8); ROUND( 9); ROUND(10); ROUND(11);
   ROUND(12); ROUND(13); ROUND(14); ROUND(15);
#endif

#undef ROUND

   a ^= RC[16];
   THETA(key->noekeon.K, a, b, c, d);
   
   STORE32L(a,&ct[0]); STORE32L(b,&ct[4]);
   STORE32L(c,&ct[8]); STORE32L(d,&ct[12]);
}

#ifdef CLEAN_STACK
void noekeon_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key)
{
   _noekeon_ecb_encrypt(pt, ct, key);
   burn_stack(sizeof(ulong32) * 5 + sizeof(int));
}
#endif

#ifdef CLEAN_STACK
static void _noekeon_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key)
#else
void noekeon_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key)
#endif
{
   ulong32 a,b,c,d, temp;
#ifdef SMALL_CODE
   int r;
#endif

   _ARGCHK(key != NULL);
   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);
   
   LOAD32L(a,&ct[0]); LOAD32L(b,&ct[4]);
   LOAD32L(c,&ct[8]); LOAD32L(d,&ct[12]);
   

#ifdef SMALL_CODE

#define ROUND \
       THETA(key->noekeon.dK, a,b,c,d); \
       a ^= RC[r]; \
       PI1(a,b,c,d); \
       GAMMA(a,b,c,d); \
       PI2(a,b,c,d); 

   for (r = 16; r > 0; --r) {
       ROUND;
   }

#else

#define ROUND(i) \
       THETA(key->noekeon.dK, a,b,c,d); \
       a ^= RC[i]; \
       PI1(a,b,c,d); \
       GAMMA(a,b,c,d); \
       PI2(a,b,c,d); 

   ROUND(16); ROUND(15); ROUND(14); ROUND(13);
   ROUND(12); ROUND(11); ROUND(10); ROUND( 9);
   ROUND( 8); ROUND( 7); ROUND( 6); ROUND( 5);
   ROUND( 4); ROUND( 3); ROUND( 2); ROUND( 1);

#endif
   
#undef ROUND

   THETA(key->noekeon.dK, a,b,c,d);
   a ^= RC[0];
   STORE32L(a,&pt[0]); STORE32L(b, &pt[4]);
   STORE32L(c,&pt[8]); STORE32L(d, &pt[12]);
}

#ifdef CLEAN_STACK
void noekeon_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key)
{
   _noekeon_ecb_decrypt(ct, pt, key);
   burn_stack(sizeof(ulong32) * 5 + sizeof(int));
}
#endif

int noekeon_test(void)
{
 #ifndef LTC_TEST
    return CRYPT_NOP;
 #else
 static const struct {
     int keylen;
     unsigned char key[16], pt[16], ct[16];
 } tests[] = {
   {
      16,
      { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
      { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
      { 0x57, 0x9a, 0x6c, 0xe8, 0x91, 0x16, 0x52, 0x53,
               0x32, 0x00, 0xca, 0x0a, 0x17, 0x5d, 0x28, 0x0e }
   }
 };
 symmetric_key key;
 unsigned char tmp[2][16];
 int err, i, y;
 
 for (i = 0; i < (int)(sizeof(tests)/sizeof(tests[0])); i++) {
    zeromem(&key, sizeof(key));
    if ((err = noekeon_setup(tests[i].key, tests[i].keylen, 0, &key)) != CRYPT_OK) { 
       return err;
    }
  
    noekeon_ecb_encrypt(tests[i].pt, tmp[0], &key);
    noekeon_ecb_decrypt(tmp[0], tmp[1], &key);
    if (memcmp(tmp[0], tests[i].ct, 16) || memcmp(tmp[1], tests[i].pt, 16)) { 
#if 0
       printf("\n\nTest %d failed\n", i);
       if (memcmp(tmp[0], tests[i].ct, 16)) {
          printf("CT: ");
          for (i = 0; i < 16; i++) {
             printf("%02x ", tmp[0][i]);
          }
          printf("\n");
       } else {
          printf("PT: ");
          for (i = 0; i < 16; i++) {
             printf("%02x ", tmp[1][i]);
          }
          printf("\n");
       }
#endif       
        return CRYPT_FAIL_TESTVECTOR;
    }

      /* now see if we can encrypt all zero bytes 1000 times, decrypt and come back where we started */
      for (y = 0; y < 16; y++) tmp[0][y] = 0;
      for (y = 0; y < 1000; y++) noekeon_ecb_encrypt(tmp[0], tmp[0], &key);
      for (y = 0; y < 1000; y++) noekeon_ecb_decrypt(tmp[0], tmp[0], &key);
      for (y = 0; y < 16; y++) if (tmp[0][y] != 0) return CRYPT_FAIL_TESTVECTOR;
 }       
 return CRYPT_OK;
 #endif
}

int noekeon_keysize(int *desired_keysize)
{
   _ARGCHK(desired_keysize != NULL);
   if (*desired_keysize < 16) {
      return CRYPT_INVALID_KEYSIZE;
   } else {
      *desired_keysize = 16;
      return CRYPT_OK;
   }
}

#endif

