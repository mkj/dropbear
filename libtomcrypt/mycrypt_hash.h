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

typedef union Hash_state {
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

extern struct _hash_descriptor {
    char *name;
    unsigned char ID;
    unsigned long hashsize;       /* digest output size in bytes  */
    unsigned long blocksize;      /* the block size the hash uses */
    void (*init)(hash_state *);
    int (*process)(hash_state *, const unsigned char *, unsigned long);
    int (*done)(hash_state *, unsigned char *);
    int  (*test)(void);
} hash_descriptor[];

#ifdef SHA512
extern void sha512_init(hash_state * md);
extern int sha512_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern int sha512_done(hash_state * md, unsigned char *hash);
extern int  sha512_test(void);
extern const struct _hash_descriptor sha512_desc;
#endif

#ifdef SHA384
#ifndef SHA512
   #error SHA512 is required for SHA384
#endif
extern void sha384_init(hash_state * md);
#define sha384_process sha512_process
extern int sha384_done(hash_state * md, unsigned char *hash);
extern int  sha384_test(void);
extern const struct _hash_descriptor sha384_desc;
#endif

#ifdef SHA256
extern void sha256_init(hash_state * md);
extern int sha256_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern int sha256_done(hash_state * md, unsigned char *hash);
extern int  sha256_test(void);
extern const struct _hash_descriptor sha256_desc;

#ifdef SHA224
#ifndef SHA256
   #error SHA256 is required for SHA224
#endif
extern void sha224_init(hash_state * md);
#define sha224_process sha256_process
extern int sha224_done(hash_state * md, unsigned char *hash);
extern int  sha224_test(void);
extern const struct _hash_descriptor sha224_desc;
#endif
#endif

#ifdef SHA1
extern void sha1_init(hash_state * md);
extern int sha1_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern int sha1_done(hash_state * md, unsigned char *hash);
extern int  sha1_test(void);
extern const struct _hash_descriptor sha1_desc;
#endif

#ifdef MD5
extern void md5_init(hash_state * md);
extern int md5_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern int md5_done(hash_state * md, unsigned char *hash);
extern int  md5_test(void);
extern const struct _hash_descriptor md5_desc;
#endif

#ifdef MD4
extern void md4_init(hash_state * md);
extern int md4_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern int md4_done(hash_state * md, unsigned char *hash);
extern int  md4_test(void);
extern const struct _hash_descriptor md4_desc;
#endif

#ifdef MD2
extern void md2_init(hash_state * md);
extern int md2_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern int md2_done(hash_state * md, unsigned char *hash);
extern int  md2_test(void);
extern const struct _hash_descriptor md2_desc;
#endif

#ifdef TIGER
extern void tiger_init(hash_state * md);
extern int tiger_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern int tiger_done(hash_state * md, unsigned char *hash);
extern int  tiger_test(void);
extern const struct _hash_descriptor tiger_desc;
#endif

#ifdef RIPEMD128
extern void rmd128_init(hash_state * md);
extern int rmd128_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern int rmd128_done(hash_state * md, unsigned char *hash);
extern int  rmd128_test(void);
extern const struct _hash_descriptor rmd128_desc;
#endif

#ifdef RIPEMD160
extern void rmd160_init(hash_state * md);
extern int rmd160_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern int rmd160_done(hash_state * md, unsigned char *hash);
extern int  rmd160_test(void);
extern const struct _hash_descriptor rmd160_desc;
#endif


extern int find_hash(const char *name);
extern int find_hash_id(unsigned char ID);
extern int register_hash(const struct _hash_descriptor *hash);
extern int unregister_hash(const struct _hash_descriptor *hash);
extern int hash_is_valid(int idx);

extern int hash_memory(int hash, const unsigned char *data, unsigned long len, unsigned char *dst, unsigned long *outlen);
extern int hash_filehandle(int hash, FILE *in, unsigned char *dst, unsigned long *outlen);
extern int hash_file(int hash, const char *fname, unsigned char *dst, unsigned long *outlen);

/* a simple macro for making hash "process" functions */
#define HASH_PROCESS(func_name, compress_name, state_var, block_size)                       \
int func_name (hash_state * md, const unsigned char *buf, unsigned long len)               \
{                                                                                           \
    unsigned long n;                                                                        \
    _ARGCHK(md != NULL);                                                                    \
    _ARGCHK(buf != NULL);                                                                   \
    if (md-> state_var .curlen > sizeof(md-> state_var .buf)) {                             \
       return CRYPT_INVALID_ARG;                                                            \
    }                                                                                       \
    while (len > 0) {                                                                       \
        if (md-> state_var .curlen == 0 && len >= block_size) {                             \
           compress_name (md, (unsigned char *)buf);                                        \
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
              compress_name (md, md-> state_var .buf);                                      \
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
     unsigned char  key[MAXBLOCKSIZE];
} hmac_state;

extern int hmac_init(hmac_state *hmac, int hash, const unsigned char *key, unsigned long keylen);
extern int hmac_process(hmac_state *hmac, const unsigned char *buf, unsigned long len);
extern int hmac_done(hmac_state *hmac, unsigned char *hashOut, unsigned long *outlen);
extern int hmac_test(void);
extern int hmac_memory(int hash, const unsigned char *key, unsigned long keylen,
                       const unsigned char *data, unsigned long len, 
                       unsigned char *dst, unsigned long *dstlen);
extern int hmac_file(int hash, const char *fname, const unsigned char *key,
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

extern int omac_init(omac_state *omac, int cipher, const unsigned char *key, unsigned long keylen);
extern int omac_process(omac_state *state, const unsigned char *buf, unsigned long len);
extern int omac_done(omac_state *state, unsigned char *out, unsigned long *outlen);
extern int omac_memory(int cipher, const unsigned char *key, unsigned long keylen,
                const unsigned char *msg, unsigned long msglen,
                unsigned char *out, unsigned long *outlen);
extern int omac_file(int cipher, const unsigned char *key, unsigned long keylen,
              const char *filename, unsigned char *out, unsigned long *outlen);
extern int omac_test(void);
#endif

