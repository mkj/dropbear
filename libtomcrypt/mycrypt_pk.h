/* ---- NUMBER THEORY ---- */
#ifdef MPI

#include "tommath.h"

extern int is_prime(mp_int *, int *);
extern int rand_prime(mp_int *N, long len, prng_state *prng, int wprng);
extern mp_err mp_init_multi(mp_int* mp, ...);
extern void mp_clear_multi(mp_int* mp, ...);

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
#define PK_PRIVATE_OPTIMIZED  2        /* PK private key [rsa optimized] */

/* ---- PACKET ---- */
#ifdef PACKET

extern void packet_store_header(unsigned char *dst, int section, int subsection);
extern int packet_valid_header(unsigned char *src, int section, int subsection);

#endif


/* ---- RSA ---- */
#ifdef MRSA
typedef struct Rsa_key {
    int type;
    mp_int e, d, N, qP, pQ, dP, dQ, p, q;
} rsa_key;

extern int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key);

extern int rsa_exptmod(const unsigned char *in,  unsigned long inlen, 
                             unsigned char *out, unsigned long *outlen, int which, 
                             rsa_key *key);

extern int rsa_pad(const unsigned char *in,  unsigned long inlen, 
                         unsigned char *out, unsigned long *outlen, 
                         int wprng, prng_state *prng);

extern int rsa_signpad(const unsigned char *in,  unsigned long inlen, 
                             unsigned char *out, unsigned long *outlen);

extern int rsa_depad(const unsigned char *in,  unsigned long inlen, 
                           unsigned char *out, unsigned long *outlen);

extern int rsa_signdepad(const unsigned char *in,  unsigned long inlen,
                               unsigned char *out, unsigned long *outlen);


extern void rsa_free(rsa_key *key);

extern int rsa_encrypt_key(const unsigned char *inkey, unsigned long inlen,
                                 unsigned char *outkey, unsigned long *outlen,
                                 prng_state *prng, int wprng, rsa_key *key);

extern int rsa_decrypt_key(const unsigned char *in, unsigned long inlen,
                                 unsigned char *outkey, unsigned long *keylen, 
                                 rsa_key *key);

extern int rsa_sign_hash(const unsigned char *in,  unsigned long inlen, 
                               unsigned char *out, unsigned long *outlen, 
                               rsa_key *key);

extern int rsa_verify_hash(const unsigned char *sig, unsigned long siglen,
                           const unsigned char *hash, int *stat, rsa_key *key);

extern int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key);
extern int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key);
#endif

/* ---- DH Routines ---- */
#ifdef MDH 

typedef struct Dh_key {
    int idx, type;
    mp_int x, y;
} dh_key;

extern int dh_test(void);
extern void dh_sizes(int *low, int *high);
extern int dh_get_size(dh_key *key);

extern int dh_make_key(prng_state *prng, int wprng, int keysize, dh_key *key);
extern void dh_free(dh_key *key);

extern int dh_export(unsigned char *out, unsigned long *outlen, int type, dh_key *key);
extern int dh_import(const unsigned char *in, unsigned long inlen, dh_key *key);

extern int dh_shared_secret(dh_key *private_key, dh_key *public_key,
                            unsigned char *out, unsigned long *outlen);

extern int dh_encrypt_key(const unsigned char *inkey, unsigned long keylen,
                                unsigned char *out,  unsigned long *len, 
                                prng_state *prng, int wprng, int hash, 
                                dh_key *key);

extern int dh_decrypt_key(const unsigned char *in,  unsigned long inlen, 
                                unsigned char *outkey, unsigned long *keylen, 
                                dh_key *key);

extern int dh_sign_hash(const unsigned char *in,  unsigned long inlen,
                              unsigned char *out, unsigned long *outlen,
                              prng_state *prng, int wprng, dh_key *key);

extern int dh_verify_hash(const unsigned char *sig, unsigned long siglen,
                          const unsigned char *hash, unsigned long hashlen, 
                                int *stat, dh_key *key);


#endif

/* ---- ECC Routines ---- */
#ifdef MECC
typedef struct {
    mp_int x, y;
} ecc_point;

typedef struct {
    int type, idx;
    ecc_point pubkey;
    mp_int k;
} ecc_key;

extern int ecc_test(void);
extern void ecc_sizes(int *low, int *high);
extern int ecc_get_size(ecc_key *key);

extern int ecc_make_key(prng_state *prng, int wprng, int keysize, ecc_key *key);
extern void ecc_free(ecc_key *key);

extern int ecc_export(unsigned char *out, unsigned long *outlen, int type, ecc_key *key);
extern int ecc_import(const unsigned char *in, unsigned long inlen, ecc_key *key);

extern int ecc_shared_secret(ecc_key *private_key, ecc_key *public_key, 
                             unsigned char *out, unsigned long *outlen);

extern int ecc_encrypt_key(const unsigned char *inkey, unsigned long keylen,
                                 unsigned char *out,  unsigned long *len, 
                                 prng_state *prng, int wprng, int hash, 
                                 ecc_key *key);

extern int ecc_decrypt_key(const unsigned char *in, unsigned long inlen,
                                 unsigned char *outkey, unsigned long *keylen, 
                                 ecc_key *key);

extern int ecc_sign_hash(const unsigned char *in,  unsigned long inlen,
                               unsigned char *out, unsigned long *outlen,
                               prng_state *prng, int wprng, ecc_key *key);

extern int ecc_verify_hash(const unsigned char *sig,  unsigned long siglen,
                           const unsigned char *hash, unsigned long hashlen, 
                                 int *stat, ecc_key *key);
#endif

#ifdef MDSA

typedef struct {
   int type, qord;
   mp_int g, q, p, x, y;
} dsa_key;

extern int dsa_make_key(prng_state *prng, int wprng, int group_size, int modulus_size, dsa_key *key);
extern void dsa_free(dsa_key *key);

extern int dsa_sign_hash(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng, dsa_key *key);

extern int dsa_verify_hash(const unsigned char *sig, unsigned long siglen,
                           const unsigned char *hash, unsigned long inlen, 
                           int *stat, dsa_key *key);

extern int dsa_import(const unsigned char *in, unsigned long inlen, dsa_key *key);

extern int dsa_export(unsigned char *out, unsigned long *outlen, int type, dsa_key *key);

extern int dsa_verify_key(dsa_key *key, int *stat);

#endif
