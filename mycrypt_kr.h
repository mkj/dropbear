#ifdef KR

#if !defined(MRSA) || !defined(MDH) || !defined(MECC)
    #error "Keyring code requires all three public key algorithms."
#endif

#define MAXLEN    256

enum {
   NON_KEY=0,
   RSA_KEY,
   DH_KEY,
   ECC_KEY
};

typedef union {
    rsa_key rsa;
    dh_key  dh;
    ecc_key ecc;
} _pk_key;

typedef struct Pk_key {
    int     key_type,             /* PUBLIC, PRIVATE, PRIVATE_OPTIMIZED */
            system;               /* RSA, ECC or DH ?   */

    unsigned char 
            name[MAXLEN],         /* various info's about this key */
            email[MAXLEN],
            description[MAXLEN];

    unsigned long ID;             /* CRC32 of the name/email/description together */

    _pk_key key;

    struct Pk_key  *next;         /* linked list chain */
} pk_key;

extern int kr_init(pk_key **pk);

extern unsigned long kr_crc(const unsigned char *name, const unsigned char *email, const unsigned char *description);

extern pk_key *kr_find(pk_key *pk, unsigned long ID);
extern pk_key *kr_find_name(pk_key *pk, const char *name);

extern int kr_add(pk_key *pk, int key_type, int sys, const unsigned char *name, 
                  const unsigned char *email, const unsigned char *description, const _pk_key *key);
                  
extern int kr_del(pk_key **_pk, unsigned long ID);
extern int kr_clear(pk_key **pk);
extern int kr_make_key(pk_key *pk, prng_state *prng, int wprng, 
                       int sys, int keysize, const unsigned char *name,
                       const unsigned char *email, const unsigned char *description);

extern int kr_export(pk_key *pk, unsigned long ID, int key_type, unsigned char *out, unsigned long *outlen);
extern int kr_import(pk_key *pk, const unsigned char *in, unsigned long inlen);

extern int kr_load(pk_key **pk, FILE *in, symmetric_CTR *ctr);
extern int kr_save(pk_key *pk, FILE *out, symmetric_CTR *ctr);

extern int kr_encrypt_key(pk_key *pk, unsigned long ID, 
                          const unsigned char *in, unsigned long inlen,
                          unsigned char *out, unsigned long *outlen,
                          prng_state *prng, int wprng, int hash);

extern int kr_decrypt_key(pk_key *pk, const unsigned char *in,
                          unsigned char *out, unsigned long *outlen);

extern int kr_sign_hash(pk_key *pk, unsigned long ID, 
                        const unsigned char *in, unsigned long inlen,
                        unsigned char *out, unsigned long *outlen,
                        prng_state *prng, int wprng);

extern int kr_verify_hash(pk_key *pk, const unsigned char *in, 
                          const unsigned char *hash, unsigned long hashlen,
                          int *stat);

extern int kr_fingerprint(pk_key *pk, unsigned long ID, int hash,
                          unsigned char *out, unsigned long *outlen);

#endif

