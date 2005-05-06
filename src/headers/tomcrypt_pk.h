/* ---- NUMBER THEORY ---- */
#ifdef MPI

#include "ltc_tommath.h"

/* in/out macros */
#define OUTPUT_BIGNUM(num, out, y, z)                                                             \
{                                                                                                 \
      if ((y + 4) > *outlen) { return CRYPT_BUFFER_OVERFLOW; }                                    \
      z = (unsigned long)mp_unsigned_bin_size(num);                                               \
      STORE32L(z, out+y);                                                                         \
      y += 4;                                                                                     \
      if ((y + z) > *outlen) { return CRYPT_BUFFER_OVERFLOW; }                                    \
      if ((err = mp_to_unsigned_bin(num, out+y)) != MP_OKAY) { return mpi_to_ltc_error(err); }    \
      y += z;                                                                                     \
}


#define INPUT_BIGNUM(num, in, x, y, inlen)                       \
{                                                                \
     /* load value */                                            \
     if ((y + 4) > inlen) {                                      \
        err = CRYPT_INVALID_PACKET;                              \
        goto error;                                              \
     }                                                           \
     LOAD32L(x, in+y);                                           \
     y += 4;                                                     \
                                                                 \
     /* sanity check... */                                       \
     if ((x+y) > inlen) {                                        \
        err = CRYPT_INVALID_PACKET;                              \
        goto error;                                              \
     }                                                           \
                                                                 \
     /* load it */                                               \
     if ((err = mp_read_unsigned_bin(num, (unsigned char *)in+y, (int)x)) != MP_OKAY) {\
        err = mpi_to_ltc_error(err);                             \
        goto error;                                              \
     }                                                           \
     y += x;                                                     \
     if ((err = mp_shrink(num)) != MP_OKAY) {                    \
        err = mpi_to_ltc_error(err);                             \
        goto error;                                              \
     }                                                           \
}

 int is_prime(mp_int *, int *);
 int rand_prime(mp_int *N, long len, prng_state *prng, int wprng);

#else
   #ifdef MRSA
      #error RSA requires the big int library 
   #endif
   #ifdef MECC
      #error ECC requires the big int library 
   #endif
   #ifdef MDH
      #error DH requires the big int library 
   #endif
   #ifdef MDSA
      #error DSA requires the big int library 
   #endif
#endif /* MPI */


/* ---- PUBLIC KEY CRYPTO ---- */

#define PK_PRIVATE            0        /* PK private keys */
#define PK_PUBLIC             1        /* PK public keys */

/* ---- PACKET ---- */
#ifdef PACKET

void packet_store_header(unsigned char *dst, int section, int subsection);
int packet_valid_header(unsigned char *src, int section, int subsection);

#endif


/* ---- RSA ---- */
#ifdef MRSA

/* Min and Max RSA key sizes (in bits) */
#define MIN_RSA_SIZE 1024
#define MAX_RSA_SIZE 4096

/* Stack required for temps (plus padding) */
// #define RSA_STACK    (8 + (MAX_RSA_SIZE/8))

typedef struct Rsa_key {
    int type;
    mp_int e, d, N, p, q, qP, dP, dQ;
} rsa_key;

int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key);

int rsa_exptmod(const unsigned char *in,   unsigned long inlen,
                      unsigned char *out,  unsigned long *outlen, int which,
                      rsa_key *key);

void rsa_free(rsa_key *key);

/* These use PKCS #1 v2.0 padding */
int rsa_encrypt_key(const unsigned char *in,     unsigned long inlen,
                          unsigned char *out,    unsigned long *outlen,
                    const unsigned char *lparam, unsigned long lparamlen,
                    prng_state *prng, int prng_idx, int hash_idx, rsa_key *key);
                                        
int rsa_decrypt_key(const unsigned char *in,       unsigned long inlen,
                          unsigned char *out,      unsigned long *outlen, 
                    const unsigned char *lparam,   unsigned long lparamlen,
                          int            hash_idx, int *stat,
                          rsa_key       *key);

int rsa_sign_hash(const unsigned char *in,     unsigned long  inlen, 
                        unsigned char *out,    unsigned long *outlen, 
                        prng_state    *prng,     int            prng_idx,
                        int            hash_idx, unsigned long  saltlen,
                        rsa_key *key);

int rsa_verify_hash(const unsigned char *sig,      unsigned long siglen,
                    const unsigned char *hash,     unsigned long hashlen,
                          int            hash_idx, unsigned long saltlen,
                          int           *stat,     rsa_key      *key);

/* these use PKCS #1 v1.5 padding */
int rsa_v15_encrypt_key(const unsigned char *in,    unsigned long  inlen,
                              unsigned char *out,   unsigned long *outlen,
                              prng_state    *prng,     int            prng_idx, 
                              rsa_key       *key);
         
int rsa_v15_decrypt_key(const unsigned char *in,     unsigned long  inlen,
                              unsigned char *out,    unsigned long  outlen, 
                              int           *stat,   rsa_key       *key);

int rsa_v15_sign_hash(const unsigned char *in,       unsigned long  inlen, 
                            unsigned char *out,      unsigned long *siglen, 
                            int            hash_idx, rsa_key       *key);

int rsa_v15_verify_hash(const unsigned char *sig,      unsigned long siglen,
                        const unsigned char *hash,     unsigned long hashlen,
                              int            hash_idx, int          *stat,     
                              rsa_key       *key);


/* PKCS #1 import/export */
int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key);
int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key);
                        
#endif

/* ---- DH Routines ---- */
#ifdef MDH 

typedef struct Dh_key {
    int idx, type;
    mp_int x, y;
} dh_key;

int dh_test(void);
void dh_sizes(int *low, int *high);
int dh_get_size(dh_key *key);

int dh_make_key(prng_state *prng, int wprng, int keysize, dh_key *key);
void dh_free(dh_key *key);

int dh_export(unsigned char *out, unsigned long *outlen, int type, dh_key *key);
int dh_import(const unsigned char *in, unsigned long inlen, dh_key *key);

int dh_shared_secret(dh_key        *private_key, dh_key        *public_key,
                     unsigned char *out,         unsigned long *outlen);

int dh_encrypt_key(const unsigned char *in,    unsigned long  keylen,
                         unsigned char *out,   unsigned long *outlen, 
                         prng_state    *prng,  int wprng, int hash, 
                         dh_key        *key);

int dh_decrypt_key(const unsigned char *in,  unsigned long  inlen, 
                         unsigned char *out, unsigned long *outlen, 
                         dh_key *key);

int dh_sign_hash(const unsigned char *in,   unsigned long inlen,
                       unsigned char *out,  unsigned long *outlen,
                       prng_state    *prng, int wprng, dh_key *key);

int dh_verify_hash(const unsigned char *sig,  unsigned long siglen,
                   const unsigned char *hash, unsigned long hashlen, 
                   int *stat, dh_key *key);


#endif

/* ---- ECC Routines ---- */
#ifdef MECC
typedef struct {
    mp_int x, y, z;
} ecc_point;

typedef struct {
    int type, idx;
    ecc_point pubkey;
    mp_int k;
} ecc_key;

int ecc_test(void);
void ecc_sizes(int *low, int *high);
int ecc_get_size(ecc_key *key);

int ecc_make_key(prng_state *prng, int wprng, int keysize, ecc_key *key);
void ecc_free(ecc_key *key);

int ecc_export(unsigned char *out, unsigned long *outlen, int type, ecc_key *key);
int ecc_import(const unsigned char *in, unsigned long inlen, ecc_key *key);

int ecc_shared_secret(ecc_key *private_key, ecc_key *public_key, 
                      unsigned char *out, unsigned long *outlen);

int ecc_encrypt_key(const unsigned char *in,   unsigned long inlen,
                          unsigned char *out,  unsigned long *outlen, 
                          prng_state *prng, int wprng, int hash, 
                          ecc_key *key);

int ecc_decrypt_key(const unsigned char *in,  unsigned long  inlen,
                          unsigned char *out, unsigned long *outlen, 
                          ecc_key *key);

int ecc_sign_hash(const unsigned char *in,  unsigned long inlen, 
                        unsigned char *out, unsigned long *outlen, 
                        prng_state *prng, int wprng, ecc_key *key);

int ecc_verify_hash(const unsigned char *sig,  unsigned long siglen,
                    const unsigned char *hash, unsigned long hashlen, 
                    int *stat, ecc_key *key);

#endif

#ifdef MDSA

typedef struct {
   int type, qord;
   mp_int g, q, p, x, y;
} dsa_key;

int dsa_make_key(prng_state *prng, int wprng, int group_size, int modulus_size, dsa_key *key);
void dsa_free(dsa_key *key);

int dsa_sign_hash(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng, dsa_key *key);

int dsa_verify_hash(const unsigned char *sig,  unsigned long siglen,
                    const unsigned char *hash, unsigned long hashlen, 
                          int           *stat, dsa_key       *key);

int dsa_import(const unsigned char *in, unsigned long inlen, dsa_key *key);

int dsa_export(unsigned char *out, unsigned long *outlen, int type, dsa_key *key);

int dsa_verify_key(dsa_key *key, int *stat);

#endif

#ifdef LTC_DER
/* DER handling */
int der_encode_integer(mp_int *num, unsigned char *out, unsigned long *outlen);
int der_decode_integer(const unsigned char *in, unsigned long *inlen, mp_int *num);
int der_length_integer(mp_int *num, unsigned long *len);
int der_put_multi_integer(unsigned char *dst, unsigned long *outlen, mp_int *num, ...);
int der_get_multi_integer(const unsigned char *src, unsigned long *inlen,  mp_int *num, ...);
#endif
