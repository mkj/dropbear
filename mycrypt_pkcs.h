/* PKCS Header Info */

/* ===> PKCS #1 -- RSA Cryptography <=== */
#ifdef PKCS_1

int pkcs_1_mgf1(const unsigned char *seed, unsigned long seedlen,
                      int            hash_idx,
                      unsigned char *mask, unsigned long masklen);

int pkcs_1_i2osp(mp_int *n, unsigned long modulus_len, unsigned char *out);
int pkcs_1_os2ip(mp_int *n, unsigned char *in, unsigned long inlen);

/* *** v2.0 padding */
int pkcs_1_oaep_encode(const unsigned char *msg,    unsigned long msglen,
                       const unsigned char *lparam, unsigned long lparamlen,
                             unsigned long modulus_bitlen, prng_state *prng,
                             int           prng_idx,         int  hash_idx,
                             unsigned char *out,    unsigned long *outlen);

int pkcs_1_oaep_decode(const unsigned char *msg,    unsigned long msglen,
                       const unsigned char *lparam, unsigned long lparamlen,
                             unsigned long modulus_bitlen, int hash_idx,
                             unsigned char *out,    unsigned long *outlen,
                             int           *res);

int pkcs_1_pss_encode(const unsigned char *msghash, unsigned long msghashlen,
                            unsigned long saltlen,  prng_state   *prng,     
                            int           prng_idx, int           hash_idx,
                            unsigned long modulus_bitlen,
                            unsigned char *out,     unsigned long *outlen);

int pkcs_1_pss_decode(const unsigned char *msghash, unsigned long msghashlen,
                      const unsigned char *sig,     unsigned long siglen,
                            unsigned long saltlen,  int           hash_idx,
                            unsigned long modulus_bitlen, int    *res);

/* *** v1.5 padding */
/* encryption padding */
int pkcs_1_v15_es_encode(const unsigned char *msg,    unsigned long msglen,
                               unsigned long  modulus_bitlen, 
                               prng_state    *prng,   int           prng_idx,
                               unsigned char *out,    unsigned long *outlen);

/* note "outlen" is fixed, you have to tell this decoder how big
 * the original message was.  Unlike the OAEP decoder it cannot auto-detect it.
 */
int pkcs_1_v15_es_decode(const unsigned char *msg,  unsigned long msglen,
                               unsigned long modulus_bitlen,
                               unsigned char *out,  unsigned long outlen,
                               int           *res);

/* signature padding */
int pkcs_1_v15_sa_encode(const unsigned char *msghash,  unsigned long msghashlen,
                               int            hash_idx, unsigned long modulus_bitlen,
                               unsigned char *out,      unsigned long *outlen);

int pkcs_1_v15_sa_decode(const unsigned char *msghash, unsigned long msghashlen,
                         const unsigned char *sig,     unsigned long siglen,
                               int           hash_idx, unsigned long modulus_bitlen, 
                               int          *res);


#endif /* PKCS_1 */

/* ===> PKCS #5 -- Password Based Cryptography <=== */
#ifdef PKCS_5

/* Algorithm #1 (old) */
int pkcs_5_alg1(const unsigned char *password, unsigned long password_len, 
                const unsigned char *salt, 
                int iteration_count,  int hash_idx,
                unsigned char *out,   unsigned long *outlen);

/* Algorithm #2 (new) */
int pkcs_5_alg2(const unsigned char *password, unsigned long password_len, 
                const unsigned char *salt,     unsigned long salt_len,
                int iteration_count,           int hash_idx,
                unsigned char *out,            unsigned long *outlen);

#endif  /* PKCS_5 */
