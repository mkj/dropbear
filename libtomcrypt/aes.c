/* This is an independent implementation of the encryption algorithm:   */
/*                                                                      */
/*         RIJNDAEL by Joan Daemen and Vincent Rijmen                   */
/*                                                                      */
/* which is a candidate algorithm in the Advanced Encryption Standard   */
/* programme of the US National Institute of Standards and Technology.  */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but I     */
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions   */
/* that the originators of the algorithm place on its exploitation.     */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     */


/* This code has been modified by Tom St Denis for libtomcrypt.a */

#include "mycrypt.h"

#ifdef RIJNDAEL

const struct _cipher_descriptor rijndael_desc =
{
    "rijndael",
    6,
    16, 32, 16, 10,
    &rijndael_setup,
    &rijndael_ecb_encrypt,
    &rijndael_ecb_decrypt,
    &rijndael_test,
    &rijndael_keysize
};

const struct _cipher_descriptor aes_desc =
{
    "aes",
    6,
    16, 32, 16, 10,
    &rijndael_setup,
    &rijndael_ecb_encrypt,
    &rijndael_ecb_decrypt,
    &rijndael_test,
    &rijndael_keysize
};

#include "aes_tab.c"

#define byte(x, y) (((x)>>(8*(y)))&255)

#define f_rn(bo, bi, n, k)                          \
    bo[n] =  ft_tab[0][byte(bi[n],0)] ^             \
             ft_tab[1][byte(bi[(n + 1) & 3],1)] ^   \
             ft_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             ft_tab[3][byte(bi[(n + 3) & 3],3)] ^ *(k + n)

#define i_rn(bo, bi, n, k)                          \
    bo[n] =  it_tab[0][byte(bi[n],0)] ^             \
             it_tab[1][byte(bi[(n + 3) & 3],1)] ^   \
             it_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             it_tab[3][byte(bi[(n + 1) & 3],3)] ^ *(k + n)

#define ls_box(x)                \
    ( fl_tab[0][byte(x, 0)] ^    \
      fl_tab[1][byte(x, 1)] ^    \
      fl_tab[2][byte(x, 2)] ^    \
      fl_tab[3][byte(x, 3)] )

#define f_rl(bo, bi, n, k)                          \
    bo[n] =  fl_tab[0][byte(bi[n],0)] ^             \
             fl_tab[1][byte(bi[(n + 1) & 3],1)] ^   \
             fl_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             fl_tab[3][byte(bi[(n + 3) & 3],3)] ^ *(k + n)

#define i_rl(bo, bi, n, k)                          \
    bo[n] =  il_tab[0][byte(bi[n],0)] ^             \
             il_tab[1][byte(bi[(n + 3) & 3],1)] ^   \
             il_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             il_tab[3][byte(bi[(n + 1) & 3],3)] ^ *(k + n)

#define star_x(x) (((x) & 0x7f7f7f7fUL) << 1) ^ ((((x) & 0x80808080UL) >> 7) * 0x1bUL)

#define imix_col(y,x)       \
    u   = star_x(x);        \
    v   = star_x(u);        \
    w   = star_x(v);        \
    t   = w ^ (x);          \
   (y)  = u ^ v ^ w;        \
   (y) ^= ROR(u ^ t,  8) ^  \
          ROR(v ^ t, 16) ^  \
          ROR(t,24)

#ifdef CLEAN_STACK
static int _rijndael_setup(const unsigned char *key, int keylen, int numrounds, symmetric_key *skey)
#else
int rijndael_setup(const unsigned char *key, int keylen, int numrounds, symmetric_key *skey)
#endif
{
    unsigned long  t, u, v, w, in_key[8];
    int i, k_len;

    /* check arguments */
    _ARGCHK(key  != NULL);
    _ARGCHK(skey != NULL);

    if (numrounds == 0) { 
       numrounds = 10 + (2 * ((keylen/8)-2));
    }       

    if (keylen != 16 && keylen != 24 && keylen != 32) {
       return CRYPT_INVALID_KEYSIZE;
    }

    if (numrounds != (10 + (2 * ((keylen/8)-2)))) {
       return CRYPT_INVALID_ROUNDS;
    }

    k_len = keylen / 4;
    for (i = 0; i < k_len; i++) {
        LOAD32L(in_key[i], key+(4*i));
    }

    skey->rijndael.k_len = k_len;
    skey->rijndael.eK[0] = in_key[0]; skey->rijndael.eK[1] = in_key[1];
    skey->rijndael.eK[2] = in_key[2]; skey->rijndael.eK[3] = in_key[3];

    switch(k_len) {
    case 4: t = skey->rijndael.eK[3];
            for(i = 0; i < 10; ++i) {
               t = ls_box(ROR(t,  8)) ^ rco_tab[i];
               t ^= skey->rijndael.eK[4 * i];     skey->rijndael.eK[4 * i + 4] = t;
               t ^= skey->rijndael.eK[4 * i + 1]; skey->rijndael.eK[4 * i + 5] = t;
               t ^= skey->rijndael.eK[4 * i + 2]; skey->rijndael.eK[4 * i + 6] = t;
               t ^= skey->rijndael.eK[4 * i + 3]; skey->rijndael.eK[4 * i + 7] = t;
            }
            break;
    case 6: skey->rijndael.eK[4]     = in_key[4]; 
            t = skey->rijndael.eK[5] = in_key[5];
            for(i = 0; i < 8; ++i) {
              t = ls_box(ROR(t,  8)) ^ rco_tab[i];
              t ^= skey->rijndael.eK[6 * i];     skey->rijndael.eK[6 * i + 6] = t;
              t ^= skey->rijndael.eK[6 * i + 1]; skey->rijndael.eK[6 * i + 7] = t;
              t ^= skey->rijndael.eK[6 * i + 2]; skey->rijndael.eK[6 * i + 8] = t;
              t ^= skey->rijndael.eK[6 * i + 3]; skey->rijndael.eK[6 * i + 9] = t;
              t ^= skey->rijndael.eK[6 * i + 4]; skey->rijndael.eK[6 * i + 10] = t;
              t ^= skey->rijndael.eK[6 * i + 5]; skey->rijndael.eK[6 * i + 11] = t;
            }
            break;
    case 8: skey->rijndael.eK[4]     = in_key[4]; 
            skey->rijndael.eK[5]     = in_key[5];
            skey->rijndael.eK[6]     = in_key[6]; 
            t = skey->rijndael.eK[7] = in_key[7];
            for(i = 0; i < 7; ++i) {
               t = ls_box(ROR(t,  8)) ^ rco_tab[i];
               t ^= skey->rijndael.eK[8 * i];     skey->rijndael.eK[8 * i + 8] = t;
               t ^= skey->rijndael.eK[8 * i + 1]; skey->rijndael.eK[8 * i + 9] = t;
               t ^= skey->rijndael.eK[8 * i + 2]; skey->rijndael.eK[8 * i + 10] = t;
               t ^= skey->rijndael.eK[8 * i + 3]; skey->rijndael.eK[8 * i + 11] = t;

               t  = skey->rijndael.eK[8 * i + 4] ^ ls_box(t); skey->rijndael.eK[8 * i + 12] = t;
               t ^= skey->rijndael.eK[8 * i + 5]; skey->rijndael.eK[8 * i + 13] = t;
               t ^= skey->rijndael.eK[8 * i + 6]; skey->rijndael.eK[8 * i + 14] = t;
               t ^= skey->rijndael.eK[8 * i + 7]; skey->rijndael.eK[8 * i + 15] = t;
            }
            break;
    }

    skey->rijndael.dK[0] = skey->rijndael.eK[0];
    skey->rijndael.dK[1] = skey->rijndael.eK[1];
    skey->rijndael.dK[2] = skey->rijndael.eK[2];
    skey->rijndael.dK[3] = skey->rijndael.eK[3];
    for(i = 4; i < 4 * k_len + 24; ++i) {
        imix_col(skey->rijndael.dK[i], skey->rijndael.eK[i]);
    }
    return CRYPT_OK;
};

#ifdef CLEAN_STACK
int rijndael_setup(const unsigned char *key, int keylen, int numrounds, symmetric_key *skey)
{
   int x;
   x = _rijndael_setup(key, keylen, numrounds, skey);
   burn_stack(sizeof(unsigned long) * 12 + sizeof(int) * 2);
   return x;
}
#endif

/* encrypt a block of text  */

#define f_nround(bo, bi, k) \
    f_rn(bo, bi, 0, k);     \
    f_rn(bo, bi, 1, k);     \
    f_rn(bo, bi, 2, k);     \
    f_rn(bo, bi, 3, k);     \
    k += 4

#define f_lround(bo, bi, k) \
    f_rl(bo, bi, 0, k);     \
    f_rl(bo, bi, 1, k);     \
    f_rl(bo, bi, 2, k);     \
    f_rl(bo, bi, 3, k)
    
#ifdef SMALL_CODE

static void _fnround(unsigned long *bo, unsigned long *bi, unsigned long *k)
{
   f_nround(bo, bi, k);
}

static void _flround(unsigned long *bo, unsigned long *bi, unsigned long *k)
{
   f_lround(bo, bi, k);
} 

#undef   f_nround
#define  f_nround(bo, bi, k) { _fnround(bo, bi, k); k += 4; }

#undef   f_lround
#define  f_lround(bo, bi, k) _flround(bo, bi, k)

#endif

void rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{   
    unsigned long  b0[4], b1[4], *kp;

    _ARGCHK(pt != NULL);
    _ARGCHK(ct != NULL);
    _ARGCHK(skey != NULL);

    LOAD32L(b0[0], &pt[0]); LOAD32L(b0[1], &pt[4]);
    LOAD32L(b0[2], &pt[8]); LOAD32L(b0[3], &pt[12]);
    b0[0] ^= skey->rijndael.eK[0]; b0[1] ^= skey->rijndael.eK[1];
    b0[2] ^= skey->rijndael.eK[2]; b0[3] ^= skey->rijndael.eK[3];
    kp = skey->rijndael.eK + 4;

    if (skey->rijndael.k_len > 6) {
        f_nround(b1, b0, kp); f_nround(b0, b1, kp);
        f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    } else if (skey->rijndael.k_len > 4) {
        f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    }

    f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    f_nround(b1, b0, kp); f_lround(b0, b1, kp);

    STORE32L(b0[0], &ct[0]); STORE32L(b0[1], &ct[4]);
    STORE32L(b0[2], &ct[8]); STORE32L(b0[3], &ct[12]);
#ifdef CLEAN_STACK
    zeromem(b0, sizeof(b0));
    zeromem(b1, sizeof(b1));
#endif
};

/* decrypt a block of text  */
#define i_nround(bo, bi, k) \
    i_rn(bo, bi, 0, k);     \
    i_rn(bo, bi, 1, k);     \
    i_rn(bo, bi, 2, k);     \
    i_rn(bo, bi, 3, k);     \
    k -= 4

#define i_lround(bo, bi, k) \
    i_rl(bo, bi, 0, k);     \
    i_rl(bo, bi, 1, k);     \
    i_rl(bo, bi, 2, k);     \
    i_rl(bo, bi, 3, k)
    
#ifdef SMALL_CODE

static void _inround(unsigned long *bo, unsigned long *bi, unsigned long *k)
{
   i_nround(bo, bi, k);
}

static void _ilround(unsigned long *bo, unsigned long *bi, unsigned long *k)
{
   i_lround(bo, bi, k);
} 

#undef   i_nround
#define  i_nround(bo, bi, k) { _inround(bo, bi, k); k -= 4; }

#undef   i_lround
#define  i_lround(bo, bi, k) _ilround(bo, bi, k)

#endif    

void rijndael_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey)
{   
    unsigned long b0[4], b1[4], *kp;

    _ARGCHK(pt != NULL);
    _ARGCHK(ct != NULL);
    _ARGCHK(skey != NULL);

    LOAD32L(b0[0], &ct[0]); LOAD32L(b0[1], &ct[4]);
    LOAD32L(b0[2], &ct[8]); LOAD32L(b0[3], &ct[12]);
    b0[0] ^= skey->rijndael.eK[4 * skey->rijndael.k_len + 24]; 
    b0[1] ^= skey->rijndael.eK[4 * skey->rijndael.k_len + 25];
    b0[2] ^= skey->rijndael.eK[4 * skey->rijndael.k_len + 26]; 
    b0[3] ^= skey->rijndael.eK[4 * skey->rijndael.k_len + 27];
    kp = skey->rijndael.dK + 4 * (skey->rijndael.k_len + 5);

    if(skey->rijndael.k_len > 6) {
        i_nround(b1, b0, kp); i_nround(b0, b1, kp);
        i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    } else if(skey->rijndael.k_len > 4) {
        i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    }

    i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    i_nround(b1, b0, kp); i_lround(b0, b1, kp);

    STORE32L(b0[0], &pt[0]); STORE32L(b0[1], &pt[4]);
    STORE32L(b0[2], &pt[8]); STORE32L(b0[3], &pt[12]);
#ifdef CLEAN_STACK
    zeromem(b0, sizeof(b0));
    zeromem(b1, sizeof(b1));
#endif    
};

int rijndael_test(void)
{
 int errno;
 static const struct {
     int keylen;
     unsigned char key[32], pt[16], ct[16];
 } tests[] = {
    { 16,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a }
    }, { 
      24,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 
        0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 }
    }, {
      32,
      { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
      { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
      { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }
    }
 };
 
 symmetric_key key;
 unsigned char tmp[2][16];
 int i;
 
 for (i = 0; i < (int)(sizeof(tests)/sizeof(tests[0])); i++) {
     if ((errno = rijndael_setup(tests[i].key, tests[i].keylen, 0, &key)) != CRYPT_OK) { 
       return errno;
    }

    rijndael_ecb_encrypt(tests[i].pt, tmp[0], &key);
    rijndael_ecb_decrypt(tmp[0], tmp[1], &key);
    if (memcmp(tmp[0], tests[i].ct, 16) || memcmp(tmp[1], tests[i].pt, 16)) { 
       return CRYPT_FAIL_TESTVECTOR;
    }
 }       
 return CRYPT_OK;
}

int rijndael_keysize(int *desired_keysize)
{
   _ARGCHK(desired_keysize != NULL);

   if (*desired_keysize < 16)
      return CRYPT_INVALID_KEYSIZE;
   if (*desired_keysize < 24) {
      *desired_keysize = 16;
      return CRYPT_OK;
   } else if (*desired_keysize < 32) {
      *desired_keysize = 24;
      return CRYPT_OK;
   } else {
      *desired_keysize = 32;
      return CRYPT_OK;
   }
}

#endif

