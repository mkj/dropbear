/* ---- SYMMETRIC KEY STUFF -----
 *
 * We put each of the ciphers scheduled keys in their own structs then we put all of 
 * the key formats in one union.  This makes the function prototypes easier to use.
 */
#ifdef BLOWFISH
struct blowfish_key {
   ulong32 S[4][256];
   ulong32 K[18];
};
#endif

#ifdef RC5
struct rc5_key {
   int rounds;
   ulong32 K[50];
};
#endif

#ifdef RC6
struct rc6_key {
   ulong32 K[44];
};
#endif

#ifdef SAFERP
struct saferp_key {
   unsigned char K[33][16];
   long rounds;
};
#endif

#ifdef RIJNDAEL
struct rijndael_key {
   ulong32 eK[64], dK[64];
   int Nr;
};
#endif

#ifdef XTEA
struct xtea_key {
   unsigned long A[32], B[32];
};
#endif

#ifdef TWOFISH
#ifndef TWOFISH_SMALL
   struct twofish_key {
      ulong32 S[4][256], K[40];
   };
#else
   struct twofish_key {
      ulong32 K[40];
      unsigned char S[32], start;
   };
#endif
#endif

#ifdef SAFER
#define SAFER_K64_DEFAULT_NOF_ROUNDS     6
#define SAFER_K128_DEFAULT_NOF_ROUNDS   10
#define SAFER_SK64_DEFAULT_NOF_ROUNDS    8
#define SAFER_SK128_DEFAULT_NOF_ROUNDS  10
#define SAFER_MAX_NOF_ROUNDS            13
#define SAFER_BLOCK_LEN                  8
#define SAFER_KEY_LEN     (1 + SAFER_BLOCK_LEN * (1 + 2 * SAFER_MAX_NOF_ROUNDS))
typedef unsigned char safer_block_t[SAFER_BLOCK_LEN];
typedef unsigned char safer_key_t[SAFER_KEY_LEN];
struct safer_key { safer_key_t key; };
#endif

#ifdef RC2
struct rc2_key { unsigned xkey[64]; };
#endif

#ifdef DES
struct des_key {
    ulong32 ek[32], dk[32];
};

struct des3_key {
    ulong32 ek[3][32], dk[3][32];
};
#endif

#ifdef CAST5
struct cast5_key {
    ulong32 K[32], keylen;
};
#endif

#ifdef NOEKEON
struct noekeon_key {
    ulong32 K[4], dK[4];
};
#endif

#ifdef SKIPJACK 
struct skipjack_key {
    unsigned char key[10];
};
#endif

typedef union Symmetric_key {
#ifdef DES
   struct des_key des;
   struct des3_key des3;
#endif
#ifdef RC2
   struct rc2_key rc2;
#endif
#ifdef SAFER
   struct safer_key safer;
#endif
#ifdef TWOFISH
   struct twofish_key  twofish;
#endif
#ifdef BLOWFISH
   struct blowfish_key blowfish;
#endif
#ifdef RC5
   struct rc5_key      rc5;
#endif
#ifdef RC6
   struct rc6_key      rc6;
#endif
#ifdef SAFERP
   struct saferp_key   saferp;
#endif
#ifdef RIJNDAEL
   struct rijndael_key rijndael;
#endif
#ifdef XTEA
   struct xtea_key     xtea;
#endif
#ifdef CAST5
   struct cast5_key    cast5;
#endif
#ifdef NOEKEON
   struct noekeon_key  noekeon;
#endif   
#ifdef SKIPJACK
   struct skipjack_key skipjack;
#endif
} symmetric_key;

/* A block cipher ECB structure */
typedef struct {
   int                 cipher, blocklen;
   symmetric_key       key;
} symmetric_ECB;

/* A block cipher CFB structure */
typedef struct {
   int                 cipher, blocklen, padlen;
   unsigned char       IV[MAXBLOCKSIZE], pad[MAXBLOCKSIZE];
   symmetric_key       key;
} symmetric_CFB;

/* A block cipher OFB structure */
typedef struct {
   int                 cipher, blocklen, padlen;
   unsigned char       IV[MAXBLOCKSIZE];
   symmetric_key       key;
} symmetric_OFB;

/* A block cipher CBC structure */
typedef struct Symmetric_CBC {
   int                 cipher, blocklen;
   unsigned char       IV[MAXBLOCKSIZE];
   symmetric_key       key;
} symmetric_CBC;

/* A block cipher CTR structure */
typedef struct Symmetric_CTR {
   int                 cipher, blocklen, padlen;
   unsigned char       ctr[MAXBLOCKSIZE], pad[MAXBLOCKSIZE];
   symmetric_key       key;
} symmetric_CTR;

/* cipher descriptor table, last entry has "name == NULL" to mark the end of table */
extern  struct _cipher_descriptor {
   char *name;
   unsigned char ID;
   int  min_key_length, max_key_length, block_length, default_rounds;
   int  (*setup)(const unsigned char *key, int keylength, int num_rounds, symmetric_key *skey);
   void (*ecb_encrypt)(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
   void (*ecb_decrypt)(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
   int (*test)(void);
   int  (*keysize)(int *desired_keysize);
} cipher_descriptor[];

#ifdef BLOWFISH
extern int blowfish_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void blowfish_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void blowfish_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int blowfish_test(void);
extern int blowfish_keysize(int *desired_keysize);
extern const struct _cipher_descriptor blowfish_desc;
#endif

#ifdef RC5
extern int rc5_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void rc5_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void rc5_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int rc5_test(void);
extern int rc5_keysize(int *desired_keysize);
extern const struct _cipher_descriptor rc5_desc;
#endif

#ifdef RC6
extern int rc6_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void rc6_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void rc6_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int rc6_test(void);
extern int rc6_keysize(int *desired_keysize);
extern const struct _cipher_descriptor rc6_desc;
#endif

#ifdef RC2
extern int rc2_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void rc2_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void rc2_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int rc2_test(void);
extern int rc2_keysize(int *desired_keysize);
extern const struct _cipher_descriptor rc2_desc;
#endif

#ifdef SAFERP
extern int saferp_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void saferp_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void saferp_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int saferp_test(void);
extern int saferp_keysize(int *desired_keysize);
extern const struct _cipher_descriptor saferp_desc;
#endif

#ifdef SAFER
extern int safer_k64_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern int safer_sk64_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern int safer_k128_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern int safer_sk128_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void safer_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void safer_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);

extern int safer_k64_test(void);
extern int safer_sk64_test(void);
extern int safer_sk128_test(void);

extern int safer_64_keysize(int *desired_keysize);
extern int safer_128_keysize(int *desired_keysize);
extern const struct _cipher_descriptor safer_k64_desc, safer_k128_desc, safer_sk64_desc, safer_sk128_desc;
#endif

#ifdef RIJNDAEL

/* make aes an alias */
#define aes_setup           rijndael_setup
#define aes_ecb_encrypt     rijndael_ecb_encrypt
#define aes_ecb_decrypt     rijndael_ecb_decrypt
#define aes_test            rijndael_test
#define aes_keysize         rijndael_keysize

extern int rijndael_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void rijndael_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void rijndael_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int rijndael_test(void);
extern int rijndael_keysize(int *desired_keysize);
extern const struct _cipher_descriptor rijndael_desc, aes_desc;
#endif

#ifdef XTEA
extern int xtea_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void xtea_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void xtea_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int xtea_test(void);
extern int xtea_keysize(int *desired_keysize);
extern const struct _cipher_descriptor xtea_desc;
#endif

#ifdef TWOFISH
extern int twofish_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void twofish_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void twofish_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int twofish_test(void);
extern int twofish_keysize(int *desired_keysize);
extern const struct _cipher_descriptor twofish_desc;
#endif

#ifdef DES
extern int des_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void des_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void des_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int des_test(void);
extern int des_keysize(int *desired_keysize);

extern int des3_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void des3_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void des3_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int des3_test(void);
extern int des3_keysize(int *desired_keysize);

extern const struct _cipher_descriptor des_desc, des3_desc;
#endif

#ifdef CAST5
extern int cast5_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void cast5_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void cast5_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int cast5_test(void);
extern int cast5_keysize(int *desired_keysize);
extern const struct _cipher_descriptor cast5_desc;
#endif

#ifdef NOEKEON
extern int noekeon_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void noekeon_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void noekeon_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int noekeon_test(void);
extern int noekeon_keysize(int *desired_keysize);
extern const struct _cipher_descriptor noekeon_desc;
#endif

#ifdef SKIPJACK
extern int skipjack_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
extern void skipjack_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *key);
extern void skipjack_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *key);
extern int skipjack_test(void);
extern int skipjack_keysize(int *desired_keysize);
extern const struct _cipher_descriptor skipjack_desc;
#endif

#ifdef ECB
extern int ecb_start(int cipher, const unsigned char *key, 
                     int keylen, int num_rounds, symmetric_ECB *ecb);
extern int ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_ECB *ecb);
extern int ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_ECB *ecb);
#endif

#ifdef CFB
extern int cfb_start(int cipher, const unsigned char *IV, const unsigned char *key, 
                     int keylen, int num_rounds, symmetric_CFB *cfb);
extern int cfb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CFB *cfb);
extern int cfb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CFB *cfb);
#endif

#ifdef OFB
extern int ofb_start(int cipher, const unsigned char *IV, const unsigned char *key, 
                     int keylen, int num_rounds, symmetric_OFB *ofb);
extern int ofb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_OFB *ofb);
extern int ofb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_OFB *ofb);
#endif

#ifdef CBC
extern int cbc_start(int cipher, const unsigned char *IV, const unsigned char *key,
                     int keylen, int num_rounds, symmetric_CBC *cbc);
extern int cbc_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_CBC *cbc);
extern int cbc_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_CBC *cbc);
#endif

#ifdef CTR
extern int ctr_start(int cipher, const unsigned char *IV, const unsigned char *key, 
                     int keylen, int num_rounds, symmetric_CTR *ctr);
extern int ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CTR *ctr);
extern int ctr_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CTR *ctr);
#endif
    
extern int find_cipher(const char *name);
extern int find_cipher_any(const char *name, int blocklen, int keylen);
extern int find_cipher_id(unsigned char ID);

extern int register_cipher(const struct _cipher_descriptor *cipher);
extern int unregister_cipher(const struct _cipher_descriptor *cipher);

extern int cipher_is_valid(int idx);

