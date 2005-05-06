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
  @file ecc_sys.c
  ECC Crypto, Tom St Denis
*/
  
/**
  Encrypt a symmetric key with ECC 
  @param in         The symmetric key you want to encrypt
  @param inlen      The length of the key to encrypt (octets)
  @param out        [out] The destination for the ciphertext
  @param outlen     [in/out] The max size and resulting size of the ciphertext
  @param prng       An active PRNG state
  @param wprng      The index of the PRNG you wish to use 
  @param hash       The index of the hash you want to use 
  @param key        The ECC key you want to encrypt to
  @return CRYPT_OK if successful
*/
int ecc_encrypt_key(const unsigned char *in,   unsigned long inlen,
                          unsigned char *out,  unsigned long *outlen, 
                          prng_state *prng, int wprng, int hash, 
                          ecc_key *key)
{
    unsigned char *pub_expt, *ecc_shared, *skey;
    ecc_key        pubkey;
    unsigned long  x, y, z, hashsize, pubkeysize;
    int            err;

    LTC_ARGCHK(in      != NULL);
    LTC_ARGCHK(out     != NULL);
    LTC_ARGCHK(outlen  != NULL);
    LTC_ARGCHK(key     != NULL);

    /* check that wprng/cipher/hash are not invalid */
    if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
       return err;
    }

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
       return err;
    }

    if (inlen > hash_descriptor[hash].hashsize) {
       return CRYPT_INVALID_HASH;
    }

    /* make a random key and export the public copy */
    if ((err = ecc_make_key(prng, wprng, ecc_get_size(key), &pubkey)) != CRYPT_OK) {
       return err;
    }

    pub_expt   = XMALLOC(ECC_BUF_SIZE);
    ecc_shared = XMALLOC(ECC_BUF_SIZE);
    skey       = XMALLOC(MAXBLOCKSIZE);
    if (pub_expt == NULL || ecc_shared == NULL || skey == NULL) {
       if (pub_expt != NULL) {
          XFREE(pub_expt);
       }
       if (ecc_shared != NULL) {
          XFREE(ecc_shared);
       }
       if (skey != NULL) {
          XFREE(skey);
       }
       ecc_free(&pubkey);
       return CRYPT_MEM;
    }

    pubkeysize = ECC_BUF_SIZE;
    if ((err = ecc_export(pub_expt, &pubkeysize, PK_PUBLIC, &pubkey)) != CRYPT_OK) {
       ecc_free(&pubkey);
       goto LBL_ERR;
    }
    
    /* now check if the out buffer is big enough */
    if (*outlen < (9 + PACKET_SIZE + pubkeysize + hash_descriptor[hash].hashsize)) {
       ecc_free(&pubkey);
       err = CRYPT_BUFFER_OVERFLOW;
       goto LBL_ERR;
    }

    /* make random key */
    hashsize  = hash_descriptor[hash].hashsize;
    x = ECC_BUF_SIZE;
    if ((err = ecc_shared_secret(&pubkey, key, ecc_shared, &x)) != CRYPT_OK) {
       ecc_free(&pubkey);
       goto LBL_ERR;
    }
    ecc_free(&pubkey);
    z = MAXBLOCKSIZE;
    if ((err = hash_memory(hash, ecc_shared, x, skey, &z)) != CRYPT_OK) {
       goto LBL_ERR;
    }
    
    /* store header */
    packet_store_header(out, PACKET_SECT_ECC, PACKET_SUB_ENC_KEY);    

    /* output header */
    y = PACKET_SIZE;
 
    /* size of hash name and the name itself */
    out[y++] = hash_descriptor[hash].ID;

    /* length of ECC pubkey and the key itself */
    STORE32L(pubkeysize, out+y);
    y += 4;

    for (x = 0; x < pubkeysize; x++, y++) {
        out[y] = pub_expt[x];
    }

    STORE32L(inlen, out+y);
    y += 4;

    /* Encrypt/Store the encrypted key */
    for (x = 0; x < inlen; x++, y++) {
      out[y] = skey[x] ^ in[x];
    }
    *outlen = y;

    err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
    /* clean up */
    zeromem(pub_expt,   ECC_BUF_SIZE);
    zeromem(ecc_shared, ECC_BUF_SIZE);
    zeromem(skey,       MAXBLOCKSIZE);
#endif

    XFREE(skey);
    XFREE(ecc_shared);
    XFREE(pub_expt);

    return err;
}

/**
  Decrypt an ECC encrypted key
  @param in       The ciphertext
  @param inlen    The length of the ciphertext (octets)
  @param out      [out] The plaintext
  @param outlen   [in/out] The max size and resulting size of the plaintext
  @param key      The corresponding private ECC key
  @return CRYPT_OK if successful
*/
int ecc_decrypt_key(const unsigned char *in,  unsigned long  inlen,
                          unsigned char *out, unsigned long *outlen, 
                          ecc_key *key)
{
   unsigned char *shared_secret, *skey;
   unsigned long  x, y, z, hashsize, keysize;
   int            hash, err;
   ecc_key        pubkey;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* right key type? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }
   
   /* correct length ? */
   if (inlen < PACKET_SIZE+1+4+4) {
      return CRYPT_INVALID_PACKET;
   } else {
      inlen -= PACKET_SIZE+1+4+4;
   }

   /* is header correct? */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_ECC, PACKET_SUB_ENC_KEY)) != CRYPT_OK) {
      return err;
   }

   /* now lets get the hash name */
   y = PACKET_SIZE;
   hash = find_hash_id(in[y++]);
   if (hash == -1) {
      return CRYPT_INVALID_HASH;
   }

   /* common values */
   hashsize  = hash_descriptor[hash].hashsize;

   /* get public key */
   LOAD32L(x, in+y);
   if (inlen < x) {
      return CRYPT_INVALID_PACKET;
   } else {
      inlen -= x;
   }
   y += 4;
   if ((err = ecc_import(in+y, x, &pubkey)) != CRYPT_OK) {
      return err;
   }
   y += x;

   /* allocate memory */
   shared_secret = XMALLOC(ECC_BUF_SIZE);
   skey          = XMALLOC(MAXBLOCKSIZE);
   if (shared_secret == NULL || skey == NULL) {
      if (shared_secret != NULL) {
         XFREE(shared_secret);
      }
      if (skey != NULL) {
         XFREE(skey);
      }
      ecc_free(&pubkey);
      return CRYPT_MEM;
   }

   /* make shared key */
   x = ECC_BUF_SIZE;
   if ((err = ecc_shared_secret(key, &pubkey, shared_secret, &x)) != CRYPT_OK) {
      ecc_free(&pubkey);
      goto LBL_ERR;
   }
   ecc_free(&pubkey);

   z = MAXBLOCKSIZE;
   if ((err = hash_memory(hash, shared_secret, x, skey, &z)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   LOAD32L(keysize, in+y);
   if (inlen < keysize) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   } else {
      inlen -= keysize;
   }
   y += 4;

   if (*outlen < keysize) {
       err = CRYPT_BUFFER_OVERFLOW;
       goto LBL_ERR;
   }

   /* Decrypt the key */
   for (x = 0; x < keysize; x++, y++) {
     out[x] = skey[x] ^ in[y];
   }

   *outlen = keysize;

   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(shared_secret, ECC_BUF_SIZE);
   zeromem(skey,          MAXBLOCKSIZE);
#endif

   XFREE(skey);
   XFREE(shared_secret);

   return err;
}

/**
  Sign a message digest
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param out       [out] The destination for the signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param key       A private ECC key
  @return CRYPT_OK if successful
*/
int ecc_sign_hash(const unsigned char *in,  unsigned long inlen, 
                        unsigned char *out, unsigned long *outlen, 
                        prng_state *prng, int wprng, ecc_key *key)
{
   ecc_key       pubkey;
   mp_int        b, p;
   unsigned char *epubkey, *er;
   unsigned long x, y, pubkeysize, rsize;
   int           err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* is this a private key? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }
   
   /* is the IDX valid ?  */
   if (is_valid_idx(key->idx) != 1) {
      return CRYPT_PK_INVALID_TYPE;
   }
   
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* make up a key and export the public copy */
   if ((err = ecc_make_key(prng, wprng, ecc_get_size(key), &pubkey)) != CRYPT_OK) {
      return err;
   }

   /* allocate ram */
   epubkey = XMALLOC(ECC_BUF_SIZE);
   er      = XMALLOC(ECC_BUF_SIZE);
   if (epubkey == NULL || er == NULL) {
      if (epubkey != NULL) {
         XFREE(epubkey);
      }
      if (er != NULL) {
         XFREE(er);
      }
      ecc_free(&pubkey);
      return CRYPT_MEM;
   }

   pubkeysize = ECC_BUF_SIZE;
   if ((err = ecc_export(epubkey, &pubkeysize, PK_PUBLIC, &pubkey)) != CRYPT_OK) {
      ecc_free(&pubkey);
      goto LBL_ERR;
   }

   /* get the hash and load it as a bignum into 'b' */
   /* init the bignums */
   if ((err = mp_init_multi(&b, &p, NULL)) != MP_OKAY) { 
      ecc_free(&pubkey);
      err = mpi_to_ltc_error(err);
      goto LBL_ERR;
   }
   if ((err = mp_read_radix(&p, (char *)sets[key->idx].order, 64)) != MP_OKAY)        { goto error; }
   if ((err = mp_read_unsigned_bin(&b, (unsigned char *)in, (int)inlen)) != MP_OKAY)  { goto error; }

   /* find b = (m - x)/k */
   if ((err = mp_invmod(&pubkey.k, &p, &pubkey.k)) != MP_OKAY)            { goto error; } /* k = 1/k */
   if ((err = mp_submod(&b, &key->k, &p, &b)) != MP_OKAY)                 { goto error; } /* b = m - x */
   if ((err = mp_mulmod(&b, &pubkey.k, &p, &b)) != MP_OKAY)               { goto error; } /* b = (m - x)/k */

   /* export it */
   rsize = (unsigned long)mp_unsigned_bin_size(&b);
   if (rsize > ECC_BUF_SIZE) { 
      err = CRYPT_BUFFER_OVERFLOW;
      goto error; 
   }
   if ((err = mp_to_unsigned_bin(&b, er)) != MP_OKAY)                     { goto error; }

   /* now lets check the outlen before we write */
   if (*outlen < (12 + rsize + pubkeysize)) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   /* lets output */
   y = PACKET_SIZE;
   
   /* size of public key */
   STORE32L(pubkeysize, out+y);
   y += 4;

   /* copy the public key */
   for (x = 0; x < pubkeysize; x++, y++) {
       out[y] = epubkey[x];
   }

   /* size of 'r' */
   STORE32L(rsize, out+y);
   y += 4;

   /* copy r */
   for (x = 0; x < rsize; x++, y++) {
       out[y] = er[x];
   }

   /* store header */
   packet_store_header(out, PACKET_SECT_ECC, PACKET_SUB_SIGNED);
   *outlen = y;

   /* all ok */
   err = CRYPT_OK;
   goto LBL_ERR;
error:
   err = mpi_to_ltc_error(err);
LBL_ERR:
   mp_clear_multi(&b, &p, NULL);
   ecc_free(&pubkey);
#ifdef LTC_CLEAN_STACK
   zeromem(er,      ECC_BUF_SIZE);
   zeromem(epubkey, ECC_BUF_SIZE);
#endif

   XFREE(epubkey);
   XFREE(er);

   return err;   
}

/* verify that mG = (bA + Y)
 *
 * The signatures work by making up a fresh key "a" with a public key "A".  Now we want to sign so the 
 * public key Y = xG can verify it.
 *
 * b = (m - x)/k, A is the public key embedded and Y is the users public key [who signed it]
 * A = kG therefore bA == ((m-x)/k)kG == (m-x)G
 *
 * Adding Y = xG to the bA gives us (m-x)G + xG == mG
 *
 * The user given only xG, kG and b cannot determine k or x which means they can't find the private key.
 * 
 */

/**
   Verify an ECC signature
   @param sig         The signature to verify
   @param siglen      The length of the signature (octets)
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return CRYPT_OK if successful (even if the signature is not valid)
*/
int ecc_verify_hash(const unsigned char *sig,  unsigned long siglen,
                    const unsigned char *hash, unsigned long hashlen, 
                    int *stat, ecc_key *key)
{
   ecc_point    *mG;
   ecc_key       pubkey;
   mp_int        b, p, m, mu;
   unsigned long x, y;
   int           err;

   LTC_ARGCHK(sig  != NULL);
   LTC_ARGCHK(hash != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(key  != NULL);

   /* default to invalid signature */
   *stat = 0;

   if (siglen < PACKET_SIZE+4+4) {
      return CRYPT_INVALID_PACKET;
   } else {
      siglen -= PACKET_SIZE+4+4;
   }

   /* is the message format correct? */
   if ((err = packet_valid_header((unsigned char *)sig, PACKET_SECT_ECC, PACKET_SUB_SIGNED)) != CRYPT_OK) {
      return err;
   }     

   /* get hash name */
   y = PACKET_SIZE;

   /* get size of public key */
   LOAD32L(x, sig+y);
   if (siglen < x) {
      return CRYPT_INVALID_PACKET;
   } else {
      siglen -= x;
   }
   y += 4;

   /* load the public key */
   if ((err = ecc_import((unsigned char*)sig+y, x, &pubkey)) != CRYPT_OK) {
      return err;
   }
   y += x;

   /* load size of 'b' */
   LOAD32L(x, sig+y);
   if (siglen < x) {
      return CRYPT_INVALID_PACKET;
   } else {
      siglen -= x;
   }
   y += 4;

   /* init values */
   if ((err = mp_init_multi(&b, &m, &p, &mu, NULL)) != MP_OKAY) { 
      ecc_free(&pubkey);
      return mpi_to_ltc_error(err);
   }

   mG = new_point();
   if (mG == NULL) { 
      mp_clear_multi(&b, &m, &p, &mu, NULL);
      ecc_free(&pubkey);
      return CRYPT_MEM;
   } 

   /* load b */
   if ((err = mp_read_unsigned_bin(&b, (unsigned char *)sig+y, (int)x)) != MP_OKAY)        { goto error; }
   y += x;

   /* get m in binary a bignum */
   if ((err = mp_read_unsigned_bin(&m, (unsigned char *)hash, (int)hashlen)) != MP_OKAY)   { goto error; }
   
   /* load prime */
   if ((err = mp_read_radix(&p, (char *)sets[key->idx].prime, 64)) != MP_OKAY)             { goto error; }
   
   /* calculate barrett stuff */
   mp_set(&mu, 1); 
   mp_lshd(&mu, 2 * USED(&p));
   if ((err = mp_div(&mu, &p, &mu, NULL)) != MP_OKAY)                                      { goto error; }

   /* get bA */
   if ((err = ecc_mulmod(&b, &pubkey.pubkey, &pubkey.pubkey, &p)) != CRYPT_OK)                  { goto done; }
   
   /* get bA + Y */
   if ((err = add_point(&pubkey.pubkey, &key->pubkey, &pubkey.pubkey, &p, &mu)) != CRYPT_OK)    { goto done; }

   /* we have to transform it */
   if ((err = ecc_map(&pubkey.pubkey, &p, &mu)) != CRYPT_OK)                                    { goto done; }

   /* get mG */
   if ((err = mp_read_radix(&mG->x, (char *)sets[key->idx].Gx, 64)) != MP_OKAY)                 { goto error; }
   if ((err = mp_read_radix(&mG->y, (char *)sets[key->idx].Gy, 64)) != MP_OKAY)                 { goto error; }
   mp_set(&mG->z, 1);
   if ((err = ecc_mulmod(&m, mG, mG, &p)) != CRYPT_OK)                                          { goto done; }

   /* compare mG to bA + Y */
   if (mp_cmp(&mG->x, &pubkey.pubkey.x) == MP_EQ && mp_cmp(&mG->y, &pubkey.pubkey.y) == MP_EQ) {
      *stat = 1;
   }

   /* clear up and return */
   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   del_point(mG);
   ecc_free(&pubkey);
   mp_clear_multi(&p, &m, &b, &mu, NULL);
   return err;
}

