#include "mycrypt.h"

#ifdef RC5

const struct _cipher_descriptor rc5_desc =
{
    "rc5",
    2,
    8, 128, 8, 12,
    &rc5_setup,
    &rc5_ecb_encrypt,
    &rc5_ecb_decrypt,
    &rc5_test,
    &rc5_keysize
};

#ifdef CLEAN_STACK
static int _rc5_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
#else
int rc5_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
#endif
{
    unsigned long L[64], S[50], A, B, i, j, v, s, t, l;

    _ARGCHK(skey != NULL);
    _ARGCHK(key != NULL);

    /* test parameters */
    if (num_rounds == 0) { 
       num_rounds = rc5_desc.default_rounds;
    }

    if (num_rounds < 12 || num_rounds > 24) { 
       return CRYPT_INVALID_ROUNDS;
    }

    /* key must be between 64 and 1024 bits */
    if (keylen < 8 || keylen > 128) {
       return CRYPT_INVALID_KEYSIZE;
    }

    /* copy the key into the L array */
    for (A = i = j = 0; i < (unsigned long)keylen; ) { 
        A = (A << 8) | ((unsigned long)(key[i++] & 255));
        if ((i & 3) == 0) {
           L[j++] = BSWAP(A);
           A = 0;
        }
    }

    if ((keylen & 3) != 0) { 
       A <<= (unsigned long)((8 * (4 - (keylen&3)))); 
       L[j++] = BSWAP(A);
    }

    /* setup the S array */
    t = (unsigned long)(2 * (num_rounds + 1));
    S[0] = 0xB7E15163UL;
    for (i = 1; i < t; i++) S[i] = S[i - 1] + 0x9E3779B9UL;

    /* mix buffer */
    s = 3 * MAX(t, j);
    l = j;
    for (A = B = i = j = v = 0; v < s; v++) { 
        A = S[i] = ROL(S[i] + A + B, 3);
        B = L[j] = ROL(L[j] + A + B, (A+B));
        i = (i + 1) % t;
        j = (j + 1) % l;
    }
    
    /* copy to key */
    for (i = 0; i < t; i++) {
        skey->rc5.K[i] = S[i];
    }
    skey->rc5.rounds = num_rounds;
    return CRYPT_OK;
}

#ifdef CLEAN_STACK
int rc5_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   int x;
   x = _rc5_setup(key, keylen, num_rounds, skey);
   burn_stack(sizeof(unsigned long) * 122 + sizeof(int));
   return x;
}
#endif

#ifdef CLEAN_STACK
static void _rc5_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key)
#else
void rc5_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key)
#endif
{
   unsigned long A, B;
   int r;
   _ARGCHK(key != NULL);
   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);

   LOAD32L(A, &pt[0]);
   LOAD32L(B, &pt[4]);
   A += key->rc5.K[0];
   B += key->rc5.K[1];
   for (r = 0; r < key->rc5.rounds; r++) {
       A = ROL(A ^ B, B) + key->rc5.K[r+r+2];
       B = ROL(B ^ A, A) + key->rc5.K[r+r+3];
   }
   STORE32L(A, &ct[0]);
   STORE32L(B, &ct[4]);
}

#ifdef CLEAN_STACK
void rc5_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key)
{
   _rc5_ecb_encrypt(pt, ct, key);
   burn_stack(sizeof(unsigned long) * 2 + sizeof(int));
}
#endif

#ifdef CLEAN_STACK
static void _rc5_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key)
#else
void rc5_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key)
#endif
{
   unsigned long A, B;
   int r;
   _ARGCHK(key != NULL);
   _ARGCHK(pt != NULL);
   _ARGCHK(ct != NULL);

   LOAD32L(A, &ct[0]);
   LOAD32L(B, &ct[4]);
   for (r = key->rc5.rounds - 1; r >= 0; r--) {
       B = ROR(B - key->rc5.K[r+r+3], A) ^ A;
       A = ROR(A - key->rc5.K[r+r+2], B) ^ B;
   }
   A -= key->rc5.K[0];
   B -= key->rc5.K[1];
   STORE32L(A, &pt[0]);
   STORE32L(B, &pt[4]);
}

#ifdef CLEAN_STACK
void rc5_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key)
{
   _rc5_ecb_decrypt(ct, pt, key);
   burn_stack(sizeof(unsigned long) * 2 + sizeof(int));
}
#endif

int rc5_test(void)
{
   static const struct {
       unsigned char key[16], pt[8], ct[8];
   } tests[] = {
   {
       { 0x91, 0x5f, 0x46, 0x19, 0xbe, 0x41, 0xb2, 0x51,
         0x63, 0x55, 0xa5, 0x01, 0x10, 0xa9, 0xce, 0x91 },
       { 0x21, 0xa5, 0xdb, 0xee, 0x15, 0x4b, 0x8f, 0x6d },
       { 0xf7, 0xc0, 0x13, 0xac, 0x5b, 0x2b, 0x89, 0x52 }
   },
   {
       { 0x78, 0x33, 0x48, 0xe7, 0x5a, 0xeb, 0x0f, 0x2f,
         0xd7, 0xb1, 0x69, 0xbb, 0x8d, 0xc1, 0x67, 0x87 },
       { 0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52 },
       { 0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92 }
   },
   {
       { 0xDC, 0x49, 0xdb, 0x13, 0x75, 0xa5, 0x58, 0x4f,
         0x64, 0x85, 0xb4, 0x13, 0xb5, 0xf1, 0x2b, 0xaf },
       { 0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92 },
       { 0x65, 0xc1, 0x78, 0xb2, 0x84, 0xd1, 0x97, 0xcc }
   }
   };
   unsigned char buf[2][8];
   int x, err;
   symmetric_key key;

   for (x = 0; x < (int)(sizeof(tests) / sizeof(tests[0])); x++) {
      /* setup key */
      if ((err = rc5_setup(tests[x].key, 16, 12, &key)) != CRYPT_OK) {
         return err;
      }

      /* encrypt and decrypt */
      rc5_ecb_encrypt(tests[x].pt, buf[0], &key);
      rc5_ecb_decrypt(buf[0], buf[1], &key);

      /* compare */
      if (memcmp(buf[0], tests[x].ct, 8) != 0 || memcmp(buf[1], tests[x].pt, 8) != 0) {
         return CRYPT_FAIL_TESTVECTOR;
      }
   }
   return CRYPT_OK;
}

int rc5_keysize(int *desired_keysize)
{
   _ARGCHK(desired_keysize != NULL);
   if (*desired_keysize < 8) {
      return CRYPT_INVALID_KEYSIZE;
   } else if (*desired_keysize > 128) {
      *desired_keysize = 128;
   }
   return CRYPT_OK;
}

#endif



