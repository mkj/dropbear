/* PKCS Header Info */

/* ===> PKCS #1 -- RSA Cryptography <=== */
#ifdef PKCS_1

int pkcs_1_mgf1(const unsigned char *seed, unsigned long seedlen,
                      int            hash_idx,
                      unsigned char *mask, unsigned long masklen);

int pkcs_1_oaep_encode(const unsigned char *msg,    unsigned long msglen,
                       const unsigned char *lparam, unsigned long lparamlen,
                             unsigned long modulus_bitlen, int hash_idx,
                             int           prng_idx,    prng_state *prng,
                             unsigned char *out,    unsigned long *outlen);

int pkcs_1_oaep_decode(const unsigned char *msg,    unsigned long msglen,
                       const unsigned char *lparam, unsigned long lparamlen,
                             unsigned long modulus_bitlen, int hash_idx,
                             unsigned char *out,    unsigned long *outlen);

int pkcs_1_pss_encode(const unsigned char *msghash, unsigned long msghashlen,
                            unsigned long saltlen,  int           hash_idx,
                            int           prng_idx, prng_state   *prng,
                            unsigned long modulus_bitlen,
                            unsigned char *out,     unsigned long *outlen);

int pkcs_1_pss_decode(const unsigned char *msghash, unsigned long msghashlen,
                      const unsigned char *sig,     unsigned long siglen,
                            unsigned long saltlen,  int           hash_idx,
                            unsigned long modulus_bitlen, int    *res);

int pkcs_1_i2osp(mp_int *n, unsigned long modulus_len, unsigned char *out);
int pkcs_1_os2ip(mp_int *n, unsigned char *in, unsigned long inlen);


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
