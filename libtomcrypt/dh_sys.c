int dh_encrypt_key(const unsigned char *inkey, unsigned long keylen,
                         unsigned char *out,  unsigned long *len,
                         prng_state *prng, int wprng, int hash,
                         dh_key *key)
{
    unsigned char pub_expt[768], dh_shared[768], skey[MAXBLOCKSIZE];
    dh_key pubkey;
    unsigned long x, y, z, hashsize, pubkeysize;
    int err;

    _ARGCHK(inkey != NULL);
    _ARGCHK(out != NULL);
    _ARGCHK(len != NULL);
    _ARGCHK(key != NULL);

    /* check that wprng/hash are not invalid */
    if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
       return err;
    }

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
       return err;
    }

    if (keylen > hash_descriptor[hash].hashsize)  {
        return CRYPT_INVALID_HASH;
    }

    /* make a random key and export the public copy */
    if ((err = dh_make_key(prng, wprng, dh_get_size(key), &pubkey)) != CRYPT_OK) {
       return err;
    }

    pubkeysize = sizeof(pub_expt);
    if ((err = dh_export(pub_expt, &pubkeysize, PK_PUBLIC, &pubkey)) != CRYPT_OK) {
       dh_free(&pubkey);
       return err;
    }

    /* now check if the out buffer is big enough */
    if (*len < (9 + PACKET_SIZE + pubkeysize + keylen)) {
       dh_free(&pubkey);
       return CRYPT_BUFFER_OVERFLOW;
    }

    /* make random key */
    hashsize  = hash_descriptor[hash].hashsize;

    x = (unsigned long)sizeof(dh_shared);
    if ((err = dh_shared_secret(&pubkey, key, dh_shared, &x)) != CRYPT_OK) {
       dh_free(&pubkey);
       return err;
    }
    dh_free(&pubkey);

    z = sizeof(skey);
    if ((err = hash_memory(hash, dh_shared, x, skey, &z)) != CRYPT_OK) {
       return err;
    }

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
    STORE32L(keylen, out+y);
    y += 4;

    for (x = 0; x < keylen; x++, y++) {
      out[y] = skey[x] ^ inkey[x];
    }

    /* store header */
    packet_store_header(out, PACKET_SECT_DH, PACKET_SUB_ENC_KEY);

#ifdef CLEAN_STACK
    /* clean up */
    zeromem(pub_expt, sizeof(pub_expt));
    zeromem(dh_shared, sizeof(dh_shared));
    zeromem(skey, sizeof(skey));
#endif

    *len = y;
    return CRYPT_OK;
}

int dh_decrypt_key(const unsigned char *in, unsigned long inlen,
                         unsigned char *outkey, unsigned long *keylen, 
                         dh_key *key)
{
   unsigned char shared_secret[768], skey[MAXBLOCKSIZE];
   unsigned long x, y, z,hashsize, keysize;
   int res, hash, err;
   dh_key pubkey;

   _ARGCHK(in != NULL);
   _ARGCHK(outkey != NULL);
   _ARGCHK(keylen != NULL);
   _ARGCHK(key != NULL);

   /* right key type? */
   if (key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* check if initial header should fit */
   if (inlen < PACKET_SIZE+1+4+4) {
      return CRYPT_INVALID_PACKET;
   } else {
      inlen -= PACKET_SIZE+1+4+4;
   }

   /* is header correct? */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_DH, PACKET_SUB_ENC_KEY)) != CRYPT_OK)  {
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
   
   /* now check if the imported key will fit */
   if (inlen < x) {
      return CRYPT_INVALID_PACKET;
   } else {
      inlen -= x;
   }
   
   y += 4;
   if ((err = dh_import(in+y, x, &pubkey)) != CRYPT_OK) {
      return err;
   }
   y += x;

   /* make shared key */
   x = (unsigned long)sizeof(shared_secret);
   if ((err = dh_shared_secret(key, &pubkey, shared_secret, &x)) != CRYPT_OK) {
      dh_free(&pubkey);
      return err;
   }
   dh_free(&pubkey);

   z = sizeof(skey);
   if ((err = hash_memory(hash, shared_secret, x, skey, &z)) != CRYPT_OK) {
      return err;
   }

   /* load in the encrypted key */
   LOAD32L(keysize, in+y);
   
   /* will the outkey fit as part of the input */
   if (inlen < keysize) {
      return CRYPT_INVALID_PACKET;
   } else {
      inlen -= keysize;
   }
   
   if (keysize > *keylen) {
       res = CRYPT_BUFFER_OVERFLOW;
       goto done;
   }
   y += 4;

   *keylen = keysize;

   for (x = 0; x < keysize; x++, y++) {
      outkey[x] = skey[x] ^ in[y];
   }

   res = CRYPT_OK;
done:
#ifdef CLEAN_STACK
   zeromem(shared_secret, sizeof(shared_secret));
   zeromem(skey, sizeof(skey));
#endif
   return res;
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
int dh_sign_hash(const unsigned char *in,  unsigned long inlen,
                       unsigned char *out, unsigned long *outlen,
                       prng_state *prng, int wprng, dh_key *key)
{
   mp_int a, b, k, m, g, p, p1, tmp;
   unsigned char buf[1536];
   unsigned long x, y;
   int res, err;

   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);

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

   /* make up a random value k,
    * since the order of the group is prime
    * we need not check if gcd(k, r) is 1 
    */
   if (prng_descriptor[wprng].read(buf, sets[key->idx].size, prng) != 
       (unsigned long)(sets[key->idx].size)) {
      return CRYPT_ERROR_READPRNG;
   }

   /* init bignums */
   if ((err = mp_init_multi(&a, &b, &k, &m, &p, &g, &p1, &tmp, NULL)) != MP_OKAY) { 
      return mpi_to_ltc_error(err);
   }

   /* load k and m */
   if ((err = mp_read_unsigned_bin(&m, (unsigned char *)in, inlen)) != MP_OKAY)        { goto error; }
#ifdef FAST_PK   
   if ((err = mp_read_unsigned_bin(&k, buf, MIN(32,sets[key->idx].size))) != MP_OKAY)  { goto error; }
#else   
   if ((err = mp_read_unsigned_bin(&k, buf, sets[key->idx].size)) != MP_OKAY)          { goto error; }
#endif  

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

   /* store header  */
   y = PACKET_SIZE;

   /* now store them both (a,b) */
   x = (unsigned long)mp_unsigned_bin_size(&a);
   STORE32L(x, buf+y);  y += 4;
   if ((err = mp_to_unsigned_bin(&a, buf+y)) != MP_OKAY)                            { goto error; }
   y += x;

   x = (unsigned long)mp_unsigned_bin_size(&b);
   STORE32L(x, buf+y);  y += 4;
   if ((err = mp_to_unsigned_bin(&b, buf+y)) != MP_OKAY)                            { goto error; }
   y += x;

   /* check if size too big */
   if (*outlen < y) {
      res = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }

   /* store header */
   packet_store_header(buf, PACKET_SECT_DH, PACKET_SUB_SIGNED);

   /* store it */
   memcpy(out, buf, (size_t)y);
   *outlen = y;
#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif

   res = CRYPT_OK;
   goto done;
error:
   res = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&tmp, &p1, &g, &p, &m, &k, &b, &a, NULL);
   return res;
}

int dh_verify_hash(const unsigned char *sig, unsigned long siglen,
                   const unsigned char *hash, unsigned long hashlen, 
                         int *stat, dh_key *key)
{
   mp_int a, b, p, g, m, tmp;
   unsigned long x, y;
   int res, err;

   _ARGCHK(sig != NULL);
   _ARGCHK(hash != NULL);
   _ARGCHK(stat != NULL);
   _ARGCHK(key != NULL);

   /* default to invalid */
   *stat = 0;

   /* check initial input length */
   if (siglen < PACKET_SIZE+4+4) {
      return CRYPT_INVALID_PACKET;
   } else {
      siglen -= PACKET_SIZE + 4 + 4;
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
   LOAD32L(x, sig+y);
   if (siglen < x) {
      return CRYPT_INVALID_PACKET;
   } else {
      siglen -= x;
   }
   
   y += 4;
   if ((err = mp_read_unsigned_bin(&a, (unsigned char *)sig+y, x)) != MP_OKAY)    { goto error; }
   y += x;

   LOAD32L(x, sig+y);
   if (siglen < x) {
      return CRYPT_INVALID_PACKET;
   } else {
      siglen -= x;
   }
   y += 4;
   if ((err = mp_read_unsigned_bin(&b, (unsigned char *)sig+y, x)) != MP_OKAY)   { goto error; }
   y += x;

   /* load p and g */
   if ((err = mp_read_radix(&p, sets[key->idx].prime, 64)) != MP_OKAY)           { goto error; }
   if ((err = mp_read_radix(&g, sets[key->idx].base, 64)) != MP_OKAY)            { goto error; }

   /* load m */
   if ((err = mp_read_unsigned_bin(&m, (unsigned char *)hash, hashlen)) != MP_OKAY) { goto error; }

   /* find g^m mod p */
   if ((err = mp_exptmod(&g, &m, &p, &m)) != MP_OKAY)                            { goto error; } /* m = g^m mod p */

   /* find y^a * a^b */
   if ((err = mp_exptmod(&key->y, &a, &p, &tmp)) != MP_OKAY)                     { goto error; } /* tmp = y^a mod p */
   if ((err = mp_exptmod(&a, &b, &p, &a)) != MP_OKAY)                            { goto error; } /* a = a^b mod p */
   if ((err = mp_mulmod(&a, &tmp, &p, &a)) != MP_OKAY)                           { goto error; } /* a = y^a * a^b mod p */

   /* y^a * a^b == g^m ??? */
   if (mp_cmp(&a, &m) == 0) {
      *stat = 1;
   }

   /* clean up */
   res = CRYPT_OK;
   goto done;
error:
   res = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&tmp, &m, &g, &p, &b, &a, NULL);
   return res;
}

