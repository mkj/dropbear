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

typedef union Prng_state {
    struct yarrow_prng    yarrow;
    struct rc4_prng       rc4;
} prng_state;

extern struct _prng_descriptor {
    char *name;
    int (*start)(prng_state *);
    int (*add_entropy)(const unsigned char *, unsigned long, prng_state *);
    int (*ready)(prng_state *);
    unsigned long (*read)(unsigned char *, unsigned long len, prng_state *);
} prng_descriptor[];

#ifdef YARROW
extern int yarrow_start(prng_state *prng);
extern int yarrow_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng);
extern int yarrow_ready(prng_state *prng);
extern unsigned long yarrow_read(unsigned char *buf, unsigned long len, prng_state *prng);
extern const struct _prng_descriptor yarrow_desc;
#endif

#ifdef RC4
extern int rc4_start(prng_state *prng);
extern int rc4_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng);
extern int rc4_ready(prng_state *prng);
extern unsigned long rc4_read(unsigned char *buf, unsigned long len, prng_state *prng);
extern const struct _prng_descriptor rc4_desc;
#endif

#ifdef SPRNG
extern int sprng_start(prng_state *prng);
extern int sprng_add_entropy(const unsigned char *buf, unsigned long len, prng_state *prng);
extern int sprng_ready(prng_state *prng);
extern unsigned long sprng_read(unsigned char *buf, unsigned long len, prng_state *prng);
extern const struct _prng_descriptor sprng_desc;
#endif

extern int find_prng(const char *name);
extern int register_prng(const struct _prng_descriptor *prng);
extern int unregister_prng(const struct _prng_descriptor *prng);
extern int prng_is_valid(int idx);


/* Slow RNG you **might** be able to use to seed a PRNG with.  Be careful as this
 * might not work on all platforms as planned
 */
/* ch2-02-1 */ 
extern unsigned long rng_get_bytes(unsigned char *buf, 
                                   unsigned long len, 
                                   void (*callback)(void));
/* ch2-02-1 */

extern int rng_make_prng(int bits, int wprng, prng_state *prng, void (*callback)(void));

