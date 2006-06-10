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


int dsa_sign_hash_raw(const unsigned char *in,  unsigned long inlen,
                                   mp_int *r,   mp_int *s,
                               prng_state *prng, int wprng, dsa_key *key);

int dsa_sign_hash(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng, dsa_key *key);

int dsa_verify_hash_raw(         mp_int *r,          mp_int *s,
                    const unsigned char *hash, unsigned long hashlen, 
                                    int *stat,      dsa_key *key);

int dsa_verify_hash(const unsigned char *sig,  unsigned long siglen,
                    const unsigned char *hash, unsigned long hashlen, 
                          int           *stat, dsa_key       *key);

int dsa_import(const unsigned char *in, unsigned long inlen, dsa_key *key);

int dsa_export(unsigned char *out, unsigned long *outlen, int type, dsa_key *key);

int dsa_verify_key(dsa_key *key, int *stat);

#endif

#ifdef LTC_DER
/* DER handling */

enum {
 LTC_ASN1_EOL,
 LTC_ASN1_INTEGER,
 LTC_ASN1_SHORT_INTEGER,
 LTC_ASN1_BIT_STRING,
 LTC_ASN1_OCTET_STRING,
 LTC_ASN1_NULL,
 LTC_ASN1_OBJECT_IDENTIFIER,
 LTC_ASN1_IA5_STRING,
 LTC_ASN1_PRINTABLE_STRING,
 LTC_ASN1_UTCTIME,

 LTC_ASN1_CHOICE,
 LTC_ASN1_SEQUENCE
};

typedef struct {
   int           type;
   void         *data;
   unsigned long size;
   int           used;
} ltc_asn1_list;

#define LTC_SET_ASN1(list, index, Type, Data, Size)  \
   do {                                              \
      int LTC_MACRO_temp            = (index);       \
      ltc_asn1_list *LTC_MACRO_list = (list);        \
      LTC_MACRO_list[LTC_MACRO_temp].type = (Type);  \
      LTC_MACRO_list[LTC_MACRO_temp].data = (Data);  \
      LTC_MACRO_list[LTC_MACRO_temp].size = (Size);  \
      LTC_MACRO_list[LTC_MACRO_temp].used = 0;       \
   } while (0);

/* SEQUENCE */
int der_encode_sequence(ltc_asn1_list *list, unsigned long inlen,
                        unsigned char *out,  unsigned long *outlen);

int der_decode_sequence(const unsigned char *in,   unsigned long  inlen,
                              ltc_asn1_list *list, unsigned long  outlen);

int der_length_sequence(ltc_asn1_list *list, unsigned long inlen,
                        unsigned long *outlen);

/* VA list handy helpers */
int der_encode_sequence_multi(unsigned char *out, unsigned long *outlen, ...);
int der_decode_sequence_multi(const unsigned char *in, unsigned long inlen, ...);

/* INTEGER */
int der_encode_integer(mp_int *num, unsigned char *out, unsigned long *outlen);
int der_decode_integer(const unsigned char *in, unsigned long inlen, mp_int *num);
int der_length_integer(mp_int *num, unsigned long *len);

/* INTEGER -- handy for 0..2^32-1 values */
int der_decode_short_integer(const unsigned char *in, unsigned long inlen, unsigned long *num);
int der_encode_short_integer(unsigned long num, unsigned char *out, unsigned long *outlen);
int der_length_short_integer(unsigned long num, unsigned long *outlen);

/* BIT STRING */
int der_encode_bit_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_decode_bit_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_length_bit_string(unsigned long nbits, unsigned long *outlen);

/* OCTET STRING */
int der_encode_octet_string(const unsigned char *in, unsigned long inlen,
                                  unsigned char *out, unsigned long *outlen);
int der_decode_octet_string(const unsigned char *in, unsigned long inlen,
                                  unsigned char *out, unsigned long *outlen);
int der_length_octet_string(unsigned long noctets, unsigned long *outlen);

/* OBJECT IDENTIFIER */
int der_encode_object_identifier(unsigned long *words, unsigned long  nwords,
                                 unsigned char *out,   unsigned long *outlen);
int der_decode_object_identifier(const unsigned char *in,    unsigned long  inlen,
                                       unsigned long *words, unsigned long *outlen);
int der_length_object_identifier(unsigned long *words, unsigned long nwords, unsigned long *outlen);
unsigned long der_object_identifier_bits(unsigned long x);

/* IA5 STRING */
int der_encode_ia5_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_decode_ia5_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_length_ia5_string(const unsigned char *octets, unsigned long noctets, unsigned long *outlen);

int der_ia5_char_encode(int c);
int der_ia5_value_decode(int v);

/* Printable STRING */
int der_encode_printable_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_decode_printable_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen);
int der_length_printable_string(const unsigned char *octets, unsigned long noctets, unsigned long *outlen);

int der_printable_char_encode(int c);
int der_printable_value_decode(int v);

/* CHOICE */
int der_decode_choice(const unsigned char *in,   unsigned long *inlen,
                            ltc_asn1_list *list, unsigned long  outlen);

/* UTCTime */
typedef struct {
   unsigned YY, /* year */
            MM, /* month */
            DD, /* day */
            hh, /* hour */
            mm, /* minute */
            ss, /* second */
            off_dir, /* timezone offset direction 0 == +, 1 == - */
            off_hh, /* timezone offset hours */
            off_mm; /* timezone offset minutes */
} ltc_utctime;

int der_encode_utctime(ltc_utctime *utctime, 
                       unsigned char *out,   unsigned long *outlen);

int der_decode_utctime(const unsigned char *in, unsigned long *inlen,
                             ltc_utctime   *out);

int der_length_utctime(ltc_utctime *utctime, unsigned long *outlen);


#endif

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_pk.h,v $ */
/* $Revision: 1.30 $ */
/* $Date: 2005/06/19 11:23:03 $ */
