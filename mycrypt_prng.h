/* ---- PRNG Stuff ---- */
struct yarrow_prng {
    int                   cipher, hash;
    unsigned char         pool[MAXBLOCKSIZE];
    symmetric_CTR         ctr;
};

struct rc4_prng {
    int x, y;
    unsigned char buf[256];
};

struct fortuna_prng {
    hash_state pool[FORTUNA_POOLS];     /* the  pools */

    symmetric_key skey;

    unsigned char K[32],      /* the current key */
                  IV[16];     /* IV for CTR mode */
    
    unsigned long pool_idx,   /* current pool we will add to */
                  pool0_len,  /* length of 0'th pool */
                  wd;            

    ulong64       reset_cnt;  /* number of times we have reset */
};

struct sober128_prng {
    ulong32      R[17],          /* Working storage for the shift register */
                 initR[17],      /* saved register contents */ 
                 konst,          /* key dependent constant */
                 sbuf;           /* partial word encryption buffer */

    int          nbuf,           /* number of part-word stream bits buffered */
                 flag,           /* first add_entropy call or not? */
                 set;            /* did we call add_entropy to set key? */
    
};

typedef union Prng_state {
#ifdef YARROW
    struct yarrow_prng    yarrow;
#endif
#ifdef RC4
    struct rc4_prng       rc4;
#endif
#ifdef FORTUNA
    struct fortuna_prng   fortuna;
#endif
#ifdef SOBER128
    struct sober128_prng  sober128;
#endif
} prng_state;

extern struct _prng_descriptor {
    char *name;
    int  export_size;    /* size in bytes of exported state */
    int (*start)(prng_state *);
    int (*add_entropy)(const unsigned char *, unsigned long, prng_state *);
    int (*ready)(prng_state *);
    unsigned long (*read)(unsigned char *, unsigned long, prng_state *);
    int (*done)(prng_state *);
    int (*pexport)(unsigned char *, unsigned long *, prng_state *);
    int (*pimport)(const unsigned char *, unsigned long, prng_state *);
    int (*test)(void);
} prng_descriptor[];

#ifdef YARROW
 int yarrow_start(prng_state *prng);
 int yarrow_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng);
 int yarrow_ready(prng_state *prng);
 unsigned long yarrow_read(unsigned char *buf, unsigned long len, prng_state *prng);
 int yarrow_done(prng_state *prng);
 int  yarrow_export(unsigned char *out, unsigned long *outlen, prng_state *prng);
 int  yarrow_import(const unsigned char *in, unsigned long inlen, prng_state *prng);
 int  yarrow_test(void);
 extern const struct _prng_descriptor yarrow_desc;
#endif

#ifdef FORTUNA
 int fortuna_start(prng_state *prng);
 int fortuna_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng);
 int fortuna_ready(prng_state *prng);
 unsigned long fortuna_read(unsigned char *buf, unsigned long len, prng_state *prng);
 int fortuna_done(prng_state *prng);
 int  fortuna_export(unsigned char *out, unsigned long *outlen, prng_state *prng);
 int  fortuna_import(const unsigned char *in, unsigned long inlen, prng_state *prng);
 int  fortuna_test(void);
 extern const struct _prng_descriptor fortuna_desc;
#endif

#ifdef RC4
 int rc4_start(prng_state *prng);
 int rc4_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng);
 int rc4_ready(prng_state *prng);
 unsigned long rc4_read(unsigned char *buf, unsigned long len, prng_state *prng);
 int  rc4_done(prng_state *prng);
 int  rc4_export(unsigned char *out, unsigned long *outlen, prng_state *prng);
 int  rc4_import(const unsigned char *in, unsigned long inlen, prng_state *prng);
 int  rc4_test(void);
 extern const struct _prng_descriptor rc4_desc;
#endif

#ifdef SPRNG
 int sprng_start(prng_state *prng);
 int sprng_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng);
 int sprng_ready(prng_state *prng);
 unsigned long sprng_read(unsigned char *buf, unsigned long len, prng_state *prng);
 int sprng_done(prng_state *prng);
 int  sprng_export(unsigned char *out, unsigned long *outlen, prng_state *prng);
 int  sprng_import(const unsigned char *in, unsigned long inlen, prng_state *prng);
 int  sprng_test(void);
 extern const struct _prng_descriptor sprng_desc;
#endif

#ifdef SOBER128
 int sober128_start(prng_state *prng);
 int sober128_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng);
 int sober128_ready(prng_state *prng);
 unsigned long sober128_read(unsigned char *buf, unsigned long len, prng_state *prng);
 int sober128_done(prng_state *prng);
 int  sober128_export(unsigned char *out, unsigned long *outlen, prng_state *prng);
 int  sober128_import(const unsigned char *in, unsigned long inlen, prng_state *prng);
 int  sober128_test(void);
 extern const struct _prng_descriptor sober128_desc;
#endif

 int find_prng(const char *name);
 int register_prng(const struct _prng_descriptor *prng);
 int unregister_prng(const struct _prng_descriptor *prng);
 int prng_is_valid(int idx);

/* Slow RNG you **might** be able to use to seed a PRNG with.  Be careful as this
 * might not work on all platforms as planned
 */
unsigned long rng_get_bytes(unsigned char *buf, 
                                   unsigned long len, 
                                   void (*callback)(void));

int rng_make_prng(int bits, int wprng, prng_state *prng, void (*callback)(void));

