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
    unsigned long state[8], curlen;
    unsigned char buf[64];
};
#endif

#ifdef SHA1
struct sha1_state {
    ulong64 length;
    unsigned long state[5], curlen;
    unsigned char buf[64];
};
#endif

#ifdef MD5
struct md5_state {
    ulong64 length;
    unsigned long state[4], curlen;
    unsigned char buf[64];
};
#endif

#ifdef MD4
struct md4_state {
    ulong64 length;
    unsigned long state[4], curlen;
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
    unsigned long curlen, state[4];
};
#endif

#ifdef RIPEMD160
struct rmd160_state {
    ulong64 length;
    unsigned char buf[64];
    unsigned long curlen, state[5];
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
    void (*process)(hash_state *, const unsigned char *, unsigned long);
    void (*done)(hash_state *, unsigned char *);
    int  (*test)(void);
} hash_descriptor[];

#ifdef SHA512
extern void sha512_init(hash_state * md);
extern void sha512_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern void sha512_done(hash_state * md, unsigned char *hash);
extern int  sha512_test(void);
extern const struct _hash_descriptor sha512_desc;
#endif

#ifdef SHA384
extern void sha384_init(hash_state * md);
extern void sha384_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern void sha384_done(hash_state * md, unsigned char *hash);
extern int  sha384_test(void);
extern const struct _hash_descriptor sha384_desc;
#endif

#ifdef SHA256
extern void sha256_init(hash_state * md);
extern void sha256_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern void sha256_done(hash_state * md, unsigned char *hash);
extern int  sha256_test(void);
extern const struct _hash_descriptor sha256_desc;
#endif

#ifdef SHA1
extern void sha1_init(hash_state * md);
extern void sha1_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern void sha1_done(hash_state * md, unsigned char *hash);
extern int  sha1_test(void);
extern const struct _hash_descriptor sha1_desc;
#endif

#ifdef MD5
extern void md5_init(hash_state * md);
extern void md5_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern void md5_done(hash_state * md, unsigned char *hash);
extern int  md5_test(void);
extern const struct _hash_descriptor md5_desc;
#endif

#ifdef MD4
extern void md4_init(hash_state * md);
extern void md4_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern void md4_done(hash_state * md, unsigned char *hash);
extern int  md4_test(void);
extern const struct _hash_descriptor md4_desc;
#endif

#ifdef MD2
extern void md2_init(hash_state * md);
extern void md2_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern void md2_done(hash_state * md, unsigned char *hash);
extern int  md2_test(void);
extern const struct _hash_descriptor md2_desc;
#endif

#ifdef TIGER
extern void tiger_init(hash_state * md);
extern void tiger_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern void tiger_done(hash_state * md, unsigned char *hash);
extern int  tiger_test(void);
extern const struct _hash_descriptor tiger_desc;
#endif

#ifdef RIPEMD128
extern void rmd128_init(hash_state * md);
extern void rmd128_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern void rmd128_done(hash_state * md, unsigned char *hash);
extern int  rmd128_test(void);
extern const struct _hash_descriptor rmd128_desc;
#endif

#ifdef RIPEMD160
extern void rmd160_init(hash_state * md);
extern void rmd160_process(hash_state * md, const unsigned char *buf, unsigned long len);
extern void rmd160_done(hash_state * md, unsigned char *hash);
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

#ifdef HMAC
typedef struct Hmac_state {
     hash_state md;
     int hash;
     unsigned long hashsize; /* here for your reference */
     hash_state hashstate;
     unsigned char key[MAXBLOCKSIZE];
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
