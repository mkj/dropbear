/* ---- HASH FUNCTIONS ---- */
#ifdef SHA512
struct sha512_state {
    ulong64  length, state[8];
    unsigned long curlen;
    unsigned char buf[128];
};
#endif

#ifdef SHA256
struct sha256_state {
    ulong64 length;
    ulong32 state[8], curlen;
    unsigned char buf[64];
};
#endif

#ifdef SHA1
struct sha1_state {
    ulong64 length;
    ulong32 state[5], curlen;
    unsigned char buf[64];
};
#endif

#ifdef MD5
struct md5_state {
    ulong64 length;
    ulong32 state[4], curlen;
    unsigned char buf[64];
};
#endif

#ifdef MD4
struct md4_state {
    ulong64 length;
    ulong32 state[4], curlen;
    unsigned char buf[64];
};
#endif

#ifdef TIGER
struct tiger_state {
    ulong64 state[3], length;
    unsigned long curlen;
    unsigned char buf[64];
};
#endif

#ifdef MD2
struct md2_state {
    unsigned char chksum[16], X[48], buf[16];
    unsigned long curlen;
};
#endif

#ifdef RIPEMD128
struct rmd128_state {
    ulong64 length;
    unsigned char buf[64];
    ulong32 curlen, state[4];
};
#endif

#ifdef RIPEMD160
struct rmd160_state {
    ulong64 length;
    unsigned char buf[64];
    ulong32 curlen, state[5];
};
#endif

#ifdef WHIRLPOOL
struct whirlpool_state {
    ulong64 length, state[8];
    unsigned char buf[64];
    ulong32 curlen;
};
#endif

#ifdef CHC_HASH
struct chc_state {
    ulong64 length;
    unsigned char state[MAXBLOCKSIZE], buf[MAXBLOCKSIZE];
    ulong32 curlen;
};
#endif

typedef union Hash_state {
#ifdef CHC_HASH
    struct chc_state chc;
#endif
#ifdef WHIRLPOOL
    struct whirlpool_state whirlpool;
#endif
#ifdef SHA512
    struct sha512_state sha512;
#endif
#ifdef SHA256
    struct sha256_state sha256;
#endif
#ifdef SHA1
    struct sha1_state   sha1;
#endif
#ifdef MD5
    struct md5_state    md5;
#endif
#ifdef MD4
    struct md4_state    md4;
#endif
#ifdef MD2
    struct md2_state    md2;
#endif
#ifdef TIGER
    struct tiger_state  tiger;
#endif
#ifdef RIPEMD128
    struct rmd128_state rmd128;
#endif
#ifdef RIPEMD160
    struct rmd160_state rmd160;
#endif
} hash_state;

extern  struct _hash_descriptor {
    char *name;
    unsigned char ID;
    unsigned long hashsize;       /* digest output size in bytes  */
    unsigned long blocksize;      /* the block size the hash uses */
    unsigned char DER[64];        /* DER encoded identifier */
    unsigned long DERlen;         /* length of DER encoding */
    int (*init)(hash_state *);
    int (*process)(hash_state *, const unsigned char *, unsigned long);
    int (*done)(hash_state *, unsigned char *);
    int (*test)(void);
} hash_descriptor[];

#ifdef CHC_HASH
 int chc_register(int cipher);
 int chc_init(hash_state * md);
 int chc_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int chc_done(hash_state * md, unsigned char *hash);
 int chc_test(void);
 extern const struct _hash_descriptor chc_desc;
#endif

#ifdef WHIRLPOOL
 int whirlpool_init(hash_state * md);
 int whirlpool_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int whirlpool_done(hash_state * md, unsigned char *hash);
 int whirlpool_test(void);
 extern const struct _hash_descriptor whirlpool_desc;
#endif

#ifdef SHA512
 int sha512_init(hash_state * md);
 int sha512_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int sha512_done(hash_state * md, unsigned char *hash);
 int sha512_test(void);
 extern const struct _hash_descriptor sha512_desc;
#endif

#ifdef SHA384
#ifndef SHA512
   #error SHA512 is required for SHA384
#endif
 int sha384_init(hash_state * md);
#define sha384_process sha512_process
 int sha384_done(hash_state * md, unsigned char *hash);
 int sha384_test(void);
 extern const struct _hash_descriptor sha384_desc;
#endif

#ifdef SHA256
 int sha256_init(hash_state * md);
 int sha256_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int sha256_done(hash_state * md, unsigned char *hash);
 int sha256_test(void);
 extern const struct _hash_descriptor sha256_desc;

#ifdef SHA224
#ifndef SHA256
   #error SHA256 is required for SHA224
#endif
 int sha224_init(hash_state * md);
#define sha224_process sha256_process
 int sha224_done(hash_state * md, unsigned char *hash);
 int sha224_test(void);
 extern const struct _hash_descriptor sha224_desc;
#endif
#endif

#ifdef SHA1
 int sha1_init(hash_state * md);
 int sha1_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int sha1_done(hash_state * md, unsigned char *hash);
 int sha1_test(void);
 extern const struct _hash_descriptor sha1_desc;
#endif

#ifdef MD5
 int md5_init(hash_state * md);
 int md5_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int md5_done(hash_state * md, unsigned char *hash);
 int md5_test(void);
 extern const struct _hash_descriptor md5_desc;
#endif

#ifdef MD4
 int md4_init(hash_state * md);
 int md4_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int md4_done(hash_state * md, unsigned char *hash);
 int md4_test(void);
 extern const struct _hash_descriptor md4_desc;
#endif

#ifdef MD2
 int md2_init(hash_state * md);
 int md2_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int md2_done(hash_state * md, unsigned char *hash);
 int md2_test(void);
 extern const struct _hash_descriptor md2_desc;
#endif

#ifdef TIGER
 int tiger_init(hash_state * md);
 int tiger_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int tiger_done(hash_state * md, unsigned char *hash);
 int tiger_test(void);
 extern const struct _hash_descriptor tiger_desc;
#endif

#ifdef RIPEMD128
 int rmd128_init(hash_state * md);
 int rmd128_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int rmd128_done(hash_state * md, unsigned char *hash);
 int rmd128_test(void);
 extern const struct _hash_descriptor rmd128_desc;
#endif

#ifdef RIPEMD160
 int rmd160_init(hash_state * md);
 int rmd160_process(hash_state * md, const unsigned char *buf, unsigned long len);
 int rmd160_done(hash_state * md, unsigned char *hash);
 int rmd160_test(void);
 extern const struct _hash_descriptor rmd160_desc;
#endif

 int find_hash(const char *name);
 int find_hash_id(unsigned char ID);
 int find_hash_any(const char *name, int digestlen);
 int register_hash(const struct _hash_descriptor *hash);
 int unregister_hash(const struct _hash_descriptor *hash);
 int hash_is_valid(int idx);

 int hash_memory(int hash, const unsigned char *data, unsigned long len, unsigned char *dst, unsigned long *outlen);
 int hash_filehandle(int hash, FILE *in, unsigned char *dst, unsigned long *outlen);
 int hash_file(int hash, const char *fname, unsigned char *dst, unsigned long *outlen);

/* a simple macro for making hash "process" functions */
#define HASH_PROCESS(func_name, compress_name, state_var, block_size)                       \
int func_name (hash_state * md, const unsigned char *buf, unsigned long len)               \
{                                                                                           \
    unsigned long n;                                                                        \
    int           err;                                                                      \
    _ARGCHK(md != NULL);                                                                    \
    _ARGCHK(buf != NULL);                                                                   \
    if (md-> state_var .curlen > sizeof(md-> state_var .buf)) {                             \
       return CRYPT_INVALID_ARG;                                                            \
    }                                                                                       \
    while (len > 0) {                                                                       \
        if (md-> state_var .curlen == 0 && len >= block_size) {                             \
           if ((err = compress_name (md, (unsigned char *)buf)) != CRYPT_OK) { \
              return err;         \
           }                                        \
           md-> state_var .length += block_size * 8;                                        \
           buf             += block_size;                                                   \
           len             -= block_size;                                                   \
        } else {                                                                            \
           n = MIN(len, (block_size - md-> state_var .curlen));                             \
           memcpy(md-> state_var .buf + md-> state_var.curlen, buf, (size_t)n);             \
           md-> state_var .curlen += n;                                                     \
           buf             += n;                                                            \
           len             -= n;                                                            \
           if (md-> state_var .curlen == block_size) {                                      \
              if ((err = compress_name (md, md-> state_var .buf)) != CRYPT_OK) {\
                 return err;                                      \
              } \
              md-> state_var .length += 8*block_size;                                       \
              md-> state_var .curlen = 0;                                                   \
           }                                                                                \
       }                                                                                    \
    }                                                                                       \
    return CRYPT_OK;                                                                        \
}

#ifdef HMAC
typedef struct Hmac_state {
     hash_state     md;
     int            hash;
     hash_state     hashstate;
     unsigned char  *key;
} hmac_state;

 int hmac_init(hmac_state *hmac, int hash, const unsigned char *key, unsigned long keylen);
 int hmac_process(hmac_state *hmac, const unsigned char *buf, unsigned long len);
 int hmac_done(hmac_state *hmac, unsigned char *hashOut, unsigned long *outlen);
 int hmac_test(void);
 int hmac_memory(int hash, const unsigned char *key, unsigned long keylen,
                       const unsigned char *data, unsigned long len, 
                       unsigned char *dst, unsigned long *dstlen);
 int hmac_file(int hash, const char *fname, const unsigned char *key,
                     unsigned long keylen, 
                     unsigned char *dst, unsigned long *dstlen);
#endif

#ifdef OMAC

typedef struct {
   int             cipher_idx, 
                   buflen,
                   blklen;
   unsigned char   block[MAXBLOCKSIZE],
                   prev[MAXBLOCKSIZE],
                   Lu[2][MAXBLOCKSIZE];
   symmetric_key   key;
} omac_state;

 int omac_init(omac_state *omac, int cipher, const unsigned char *key, unsigned long keylen);
 int omac_process(omac_state *state, const unsigned char *buf, unsigned long len);
 int omac_done(omac_state *state, unsigned char *out, unsigned long *outlen);
 int omac_memory(int cipher, const unsigned char *key, unsigned long keylen,
                const unsigned char *msg, unsigned long msglen,
                unsigned char *out, unsigned long *outlen);
 int omac_file(int cipher, const unsigned char *key, unsigned long keylen,
              const char *filename, unsigned char *out, unsigned long *outlen);
 int omac_test(void);
#endif /* OMAC */

#ifdef PMAC

typedef struct {
   unsigned char     Ls[32][MAXBLOCKSIZE],    /* L shifted by i bits to the left */
                     Li[MAXBLOCKSIZE],        /* value of Li [current value, we calc from previous recall] */
                     Lr[MAXBLOCKSIZE],        /* L * x^-1 */
                     block[MAXBLOCKSIZE],     /* currently accumulated block */
                     checksum[MAXBLOCKSIZE];  /* current checksum */

   symmetric_key     key;                     /* scheduled key for cipher */
   unsigned long     block_index;             /* index # for current block */
   int               cipher_idx,              /* cipher idx */
                     block_len,               /* length of block */
                     buflen;                  /* number of bytes in the buffer */
} pmac_state;

 int pmac_init(pmac_state *pmac, int cipher, const unsigned char *key, unsigned long keylen);
 int pmac_process(pmac_state *state, const unsigned char *buf, unsigned long len);
 int pmac_done(pmac_state *state, unsigned char *out, unsigned long *outlen);

 int pmac_memory(int cipher, const unsigned char *key, unsigned long keylen,
                const unsigned char *msg, unsigned long msglen,
                unsigned char *out, unsigned long *outlen);

 int pmac_file(int cipher, const unsigned char *key, unsigned long keylen,
              const char *filename, unsigned char *out, unsigned long *outlen);

 int pmac_test(void);

/* internal functions */
 int pmac_ntz(unsigned long x);
 void pmac_shift_xor(pmac_state *pmac);

#endif /* PMAC */

#ifdef EAX_MODE

#if !(defined(OMAC) && defined(CTR))
   #error EAX_MODE requires OMAC and CTR
#endif

typedef struct {
   unsigned char N[MAXBLOCKSIZE];
   symmetric_CTR ctr;
   omac_state    headeromac, ctomac;
} eax_state;

 int eax_init(eax_state *eax, int cipher, const unsigned char *key, unsigned long keylen,
                    const unsigned char *nonce, unsigned long noncelen,
                    const unsigned char *header, unsigned long headerlen);

 int eax_encrypt(eax_state *eax, const unsigned char *pt, unsigned char *ct, unsigned long length);
 int eax_decrypt(eax_state *eax, const unsigned char *ct, unsigned char *pt, unsigned long length);
 int eax_addheader(eax_state *eax, const unsigned char *header, unsigned long length);
 int eax_done(eax_state *eax, unsigned char *tag, unsigned long *taglen);

 int eax_encrypt_authenticate_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  unsigned long noncelen,
    const unsigned char *header, unsigned long headerlen,
    const unsigned char *pt,     unsigned long ptlen,
          unsigned char *ct,
          unsigned char *tag,    unsigned long *taglen);

 int eax_decrypt_verify_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  unsigned long noncelen,
    const unsigned char *header, unsigned long headerlen,
    const unsigned char *ct,     unsigned long ctlen,
          unsigned char *pt,
          unsigned char *tag,    unsigned long taglen,
          int           *res);

 int eax_test(void);
#endif /* EAX MODE */

#ifdef OCB_MODE
typedef struct {
   unsigned char     L[MAXBLOCKSIZE],         /* L value */
                     Ls[32][MAXBLOCKSIZE],    /* L shifted by i bits to the left */
                     Li[MAXBLOCKSIZE],        /* value of Li [current value, we calc from previous recall] */
                     Lr[MAXBLOCKSIZE],        /* L * x^-1 */
                     R[MAXBLOCKSIZE],         /* R value */
                     checksum[MAXBLOCKSIZE];  /* current checksum */

   symmetric_key     key;                     /* scheduled key for cipher */
   unsigned long     block_index;             /* index # for current block */
   int               cipher,                  /* cipher idx */
                     block_len;               /* length of block */
} ocb_state;

 int ocb_init(ocb_state *ocb, int cipher, 
             const unsigned char *key, unsigned long keylen, const unsigned char *nonce);

 int ocb_encrypt(ocb_state *ocb, const unsigned char *pt, unsigned char *ct);
 int ocb_decrypt(ocb_state *ocb, const unsigned char *ct, unsigned char *pt);

 int ocb_done_encrypt(ocb_state *ocb, 
                     const unsigned char *pt,  unsigned long ptlen,
                           unsigned char *ct, 
                           unsigned char *tag, unsigned long *taglen);

 int ocb_done_decrypt(ocb_state *ocb, 
                     const unsigned char *ct,  unsigned long ctlen,
                           unsigned char *pt, 
                     const unsigned char *tag, unsigned long taglen, int *res);

 int ocb_encrypt_authenticate_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  
    const unsigned char *pt,     unsigned long ptlen,
          unsigned char *ct,
          unsigned char *tag,    unsigned long *taglen);

 int ocb_decrypt_verify_memory(int cipher,
    const unsigned char *key,    unsigned long keylen,
    const unsigned char *nonce,  
    const unsigned char *ct,     unsigned long ctlen,
          unsigned char *pt,
    const unsigned char *tag,    unsigned long taglen,
          int           *res);

 int ocb_test(void);

/* internal functions */
 void ocb_shift_xor(ocb_state *ocb, unsigned char *Z);
 int ocb_ntz(unsigned long x);
 int __ocb_done(ocb_state *ocb, const unsigned char *pt, unsigned long ptlen,
                     unsigned char *ct, unsigned char *tag, unsigned long *taglen, int mode);

#endif /* OCB_MODE */


