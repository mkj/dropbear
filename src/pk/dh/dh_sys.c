/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */

/**
  @file dh_sys.c
  DH Crypto, Tom St Denis
*/
  
/**
  Encrypt a short symmetric key with a public DH key
  @param in        The symmetric key to encrypt
  @param inlen     The length of the key (octets)
  @param out       [out] The ciphertext
  @param outlen    [in/out]  The max size and resulting size of the ciphertext
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG desired
  @param hash      The index of the hash desired (must produce a digest of size >= the size of the plaintext)
  @param key       The public key you wish to encrypt with.
  @return CRYPT_OK if successful
*/
int dh_encrypt_key(const unsigned char *in,   unsigned long inlen,
                         unsigned char *out,  unsigned long *outlen,
                         prng_state *prng, int wprng, int hash,
                         dh_key *key)
{
    unsigned char *pub_expt, *dh_shared, *skey;
    dh_key        pubkey;
    unsigned long x, y, z, hashsize, pubkeysize;
    int           err;

    LTC_ARGCHK(in != NULL);
    LTC_ARGCHK(out   != NULL);
    LTC_ARGCHK(outlen   != NULL);
    LTC_ARGCHK(key   != NULL);

    /* check that wprng/hash are not invalid */
    if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
       return err;
    }

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
       return err;
    }

    if (inlen > hash_descriptor[hash].hashsize)  {
        return CRYPT_INVALID_HASH;
    }

    /* allocate memory */
    pub_expt  = XMALLOC(DH_BUF_SIZE);
    dh_shared = XMALLOC(DH_BUF_SIZE);
    skey      = XMALLOC(MAXBLOCKSIZE);
    if (pub_expt == NULL || dh_shared == NULL || skey == NULL) {
       if (pub_expt != NULL) {
          XFREE(pub_expt);
       }
       if (dh_shared != NULL) {
          XFREE(dh_shared);
       }
       if (skey != NULL) {
          XFREE(skey);
       }
       return CRYPT_MEM;
    }

    /* make a random key and export the public copy */
    if ((err = dh_make_key(prng, wprng, dh_get_size(key), &pubkey)) != CRYPT_OK) {
       goto LBL_ERR;
    }

    pubkeysize = DH_BUF_SIZE;
    if ((err = dh_export(pub_expt, &pubkeysize, PK_PUBLIC, &pubkey)) != CRYPT_OK) {
       dh_free(&pubkey);
       goto LBL_ERR;
    }

    /* now check if the out buffer is big enough */
    if (*outlen < (1 + 4 + 4 + PACKET_SIZE + pubkeysize + inlen)) {
       dh_free(&pubkey);
       err = CRYPT_BUFFER_OVERFLOW;
       goto LBL_ERR;
    }

    /* make random key */
    hashsize  = hash_descriptor[hash].hashsize;

    x = DH_BUF_SIZE;
    if ((err = dh_shared_secret(&pubkey, key, dh_shared, &x)) != CRYPT_OK) {
       dh_free(&pubkey);
       goto LBL_ERR;
    }
    dh_free(&pubkey);

    z = MAXBLOCKSIZE;
    if ((err = hash_memory(hash, dh_shared, x, skey, &z)) != CRYPT_OK) {
       goto LBL_ERR;
    }

    /* store header */
    packet_store_header(out, PACKET_SECT_DH, PACKET_SUB_ENC_KEY);

    /* output header */
    y = PACKET_SIZE;

    /* size of hash name and the name itself */
    out[y++] = hash_descriptor[hash].ID;

    /* length of DH pubkey and the key itself */
    STORE32L(pubkeysize, out+y);
    y += 4;
    for (x = 0; x < pubkeysize; x++, y++) {
        out[y] = pub_expt[x];
    }

    /* Store the encrypted key */
    STORE32L(inlen, out+y);
    y += 4;

    for (x = 0; x < inlen; x++, y++) {
      out[y] = skey[x] ^ in[x];
    }
    *outlen = y;

    err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
    /* clean up */
    zeromem(pub_expt,  DH_BUF_SIZE);
    zeromem(dh_shared, DH_BUF_SIZE);
    zeromem(skey,      MAXBLOCKSIZE);
#endif
    XFREE(skey);
    XFREE(dh_shared);
    XFREE(pub_expt);

    return err;
}

/**
   Decrypt a DH encrypted symmetric key
   @param in       The DH encrypted packet
   @param inlen    The length of the DH encrypted packet
   @param out      The plaintext
   @param outlen   [in/out]  The max size and resulting size of the plaintext
   @param key      The private DH key corresponding to the public key that encrypted the plaintext
   @return CRYPT_OK if successful
*/
int dh_decrypt_key(const unsigned char *in, unsigned long inlen,
                         unsigned char *out, unsigned long *outlen, 
                         dh_key *key)
{
   unsigned char *shared_secret, *skey;
   unsigned long  x, y, z, hashsize, keysize;
   int            hash, err;
   dh_key         pubkey;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* right key type? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* allocate ram */
   shared_secret = XMALLOC(DH_BUF_SIZE);
   skey          = XMALLOC(MAXBLOCKSIZE);
   if (shared_secret == NULL || skey == NULL) {
      if (shared_secret != NULL) {
         XFREE(shared_secret);
      }
      if (skey != NULL) {
         XFREE(skey);
      }
      return CRYPT_MEM;
   }

   /* check if initial header should fit */
   if (inlen < PACKET_SIZE+1+4+4) {
      err =  CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   } else {
      inlen -= PACKET_SIZE+1+4+4;
   }

   /* is header correct? */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_DH, PACKET_SUB_ENC_KEY)) != CRYPT_OK)  {
      goto LBL_ERR;
   }

   /* now lets get the hash name */
   y = PACKET_SIZE;
   hash = find_hash_id(in[y++]);
   if (hash == -1) {
      err = CRYPT_INVALID_HASH;
      goto LBL_ERR;
   }

   /* common values */
   hashsize  = hash_descriptor[hash].hashsize;

   /* get public key */
   LOAD32L(x, in+y);
   
   /* now check if the imported key will fit */
   if (inlen < x) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   } else {
      inlen -= x;
   }
   
   y += 4;
   if ((err = dh_import(in+y, x, &pubkey)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   y += x;

   /* make shared key */
   x = DH_BUF_SIZE;
   if ((err = dh_shared_secret(key, &pubkey, shared_secret, &x)) != CRYPT_OK) {
      dh_free(&pubkey);
      goto LBL_ERR;
   }
   dh_free(&pubkey);

   z = MAXBLOCKSIZE;
   if ((err = hash_memory(hash, shared_secret, x, skey, &z)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* load in the encrypted key */
   LOAD32L(keysize, in+y);
   
   /* will the out fit as part of the input */
   if (inlen < keysize) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   } else {
      inlen -= keysize;
   }
   
   if (keysize > *outlen) {
       err = CRYPT_BUFFER_OVERFLOW;
       goto LBL_ERR;
   }
   y += 4;

   *outlen = keysize;

   for (x = 0; x < keysize; x++, y++) {
      out[x] = skey[x] ^ in[y];
   }

   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(shared_secret, DH_BUF_SIZE);
   zeromem(skey,          MAXBLOCKSIZE);
#endif

   XFREE(skey);
   XFREE(shared_secret);

   return err;
}

/* perform an ElGamal Signature of a hash 
 *
 * The math works as follows.  x is the private key, M is the message to sign
 
 1.  pick a random k
 2.  compute a = g^k mod p
 3.  compute b = (M - xa)/k mod p
 4.  Send (a,b)
 
 Now to verify with y=g^x mod p, a and b
 
 1.  compute y^a * a^b = g^(xa) * g^(k*(M-xa)/k)
                       = g^(xa + (M - xa))
                       = g^M [all mod p]
                       
 2.  Compare against g^M mod p [based on input hash].
 3.  If result of #2 == result of #1 then signature valid 
*/

/**
  Sign a message digest using a DH private key 
  @param in      The data to sign
  @param inlen   The length of the input (octets)
  @param out     [out] The destination of the signature
  @param outlen  [in/out] The max size and resulting size of the output
  @param prng    An active PRNG state
  @param wprng   The index of the PRNG desired
  @param key     A private DH key
  @return CRYPT_OK if successful
*/
int dh_sign_hash(const unsigned char *in,  unsigned long inlen,
                       unsigned char *out, unsigned long *outlen,
                       prng_state *prng, int wprng, dh_key *key)
{
   mp_int         a, b, k, m, g, p, p1, tmp;
   unsigned char *buf;
   unsigned long  x, y;
   int            err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* check parameters */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* is the IDX valid ?  */
   if (is_valid_idx(key->idx) != 1) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* allocate ram for buf */
   buf = XMALLOC(520);

   /* make up a random value k,
    * since the order of the group is prime
    * we need not check if gcd(k, r) is 1 
    */
   if (prng_descriptor[wprng].read(buf, sets[key->idx].size, prng) != 
       (unsigned long)(sets[key->idx].size)) {
      err = CRYPT_ERROR_READPRNG;
      goto LBL_ERR;
   }

   /* init bignums */
   if ((err = mp_init_multi(&a, &b, &k, &m, &p, &g, &p1, &tmp, NULL)) != MP_OKAY) { 
      err = mpi_to_ltc_error(err);
      goto LBL_ERR;
   }

   /* load k and m */
   if ((err = mp_read_unsigned_bin(&m, (unsigned char *)in, inlen)) != MP_OKAY)        { goto error; }
   if ((err = mp_read_unsigned_bin(&k, buf, sets[key->idx].size)) != MP_OKAY)          { goto error; }

   /* load g, p and p1 */
   if ((err = mp_read_radix(&g, sets[key->idx].base, 64)) != MP_OKAY)               { goto error; }
   if ((err = mp_read_radix(&p, sets[key->idx].prime, 64)) != MP_OKAY)              { goto error; }
   if ((err = mp_sub_d(&p, 1, &p1)) != MP_OKAY)                                     { goto error; }
   if ((err = mp_div_2(&p1, &p1)) != MP_OKAY)                                       { goto error; } /* p1 = (p-1)/2 */

   /* now get a = g^k mod p */
   if ((err = mp_exptmod(&g, &k, &p, &a)) != MP_OKAY)                               { goto error; }

   /* now find M = xa + kb mod p1 or just b = (M - xa)/k mod p1 */
   if ((err = mp_invmod(&k, &p1, &k)) != MP_OKAY)                                   { goto error; } /* k = 1/k mod p1 */
   if ((err = mp_mulmod(&a, &key->x, &p1, &tmp)) != MP_OKAY)                        { goto error; } /* tmp = xa */
   if ((err = mp_submod(&m, &tmp, &p1, &tmp)) != MP_OKAY)                           { goto error; } /* tmp = M - xa */
   if ((err = mp_mulmod(&k, &tmp, &p1, &b)) != MP_OKAY)                             { goto error; } /* b = (M - xa)/k */
   
   /* check for overflow */
   if ((unsigned long)(PACKET_SIZE + 4 + 4 + mp_unsigned_bin_size(&a) + mp_unsigned_bin_size(&b)) > *outlen) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }
   
   /* store header  */
   y = PACKET_SIZE;

   /* now store them both (a,b) */
   x = (unsigned long)mp_unsigned_bin_size(&a);
   STORE32L(x, out+y);  y += 4;
   if ((err = mp_to_unsigned_bin(&a, out+y)) != MP_OKAY)                            { goto error; }
   y += x;

   x = (unsigned long)mp_unsigned_bin_size(&b);
   STORE32L(x, out+y);  y += 4;
   if ((err = mp_to_unsigned_bin(&b, out+y)) != MP_OKAY)                            { goto error; }
   y += x;

   /* check if size too big */
   if (*outlen < y) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   /* store header */
   packet_store_header(out, PACKET_SECT_DH, PACKET_SUB_SIGNED);
   *outlen = y;

   err = CRYPT_OK;
   goto LBL_ERR;
error:
   err = mpi_to_ltc_error(err);
LBL_ERR:
   mp_clear_multi(&tmp, &p1, &g, &p, &m, &k, &b, &a, NULL);

   XFREE(buf);

   return err;
}


/**
   Verify the signature given
   @param sig        The signature
   @param siglen     The length of the signature (octets)
   @param hash       The hash that was signed
   @param hashlen    The length of the hash (octets)
   @param stat       [out] Result of signature comparison, 1==valid, 0==invalid
   @param key        The public DH key that signed the hash
   @return CRYPT_OK if succsessful (even if signature is invalid)
*/
int dh_verify_hash(const unsigned char *sig, unsigned long siglen,
                   const unsigned char *hash, unsigned long hashlen, 
                         int *stat, dh_key *key)
{
   mp_int        a, b, p, g, m, tmp;
   unsigned long x, y;
   int           err;

   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(hash != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(key  != NULL);

   /* default to invalid */
   *stat = 0;

   /* check initial input length */
   if (siglen < PACKET_SIZE+4+4) {
      return CRYPT_INVALID_PACKET;
   } 

   /* header ok? */
   if ((err = packet_valid_header((unsigned char *)sig, PACKET_SECT_DH, PACKET_SUB_SIGNED)) != CRYPT_OK) {
      return err;
   }
   
   /* get hash out of packet */
   y = PACKET_SIZE;

   /* init all bignums */
   if ((err = mp_init_multi(&a, &p, &b, &g, &m, &tmp, NULL)) != MP_OKAY) { 
      return mpi_to_ltc_error(err);
   }

   /* load a and b */
   INPUT_BIGNUM(&a, sig, x, y, siglen);
   INPUT_BIGNUM(&b, sig, x, y, siglen);

   /* load p and g */
   if ((err = mp_read_radix(&p, sets[key->idx].prime, 64)) != MP_OKAY)              { goto error1; }
   if ((err = mp_read_radix(&g, sets[key->idx].base, 64)) != MP_OKAY)               { goto error1; }

   /* load m */
   if ((err = mp_read_unsigned_bin(&m, (unsigned char *)hash, hashlen)) != MP_OKAY) { goto error1; }

   /* find g^m mod p */
   if ((err = mp_exptmod(&g, &m, &p, &m)) != MP_OKAY)                { goto error1; } /* m = g^m mod p */

   /* find y^a * a^b */
   if ((err = mp_exptmod(&key->y, &a, &p, &tmp)) != MP_OKAY)         { goto error1; } /* tmp = y^a mod p */
   if ((err = mp_exptmod(&a, &b, &p, &a)) != MP_OKAY)                { goto error1; } /* a = a^b mod p */
   if ((err = mp_mulmod(&a, &tmp, &p, &a)) != MP_OKAY)               { goto error1; } /* a = y^a * a^b mod p */

   /* y^a * a^b == g^m ??? */
   if (mp_cmp(&a, &m) == 0) {
      *stat = 1;
   }

   /* clean up */
   err = CRYPT_OK;
   goto done;
error1:
   err = mpi_to_ltc_error(err);
error:
done:
   mp_clear_multi(&tmp, &m, &g, &p, &b, &a, NULL);
   return err;
}

