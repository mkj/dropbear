/* these are smaller routines written by Clay Culver.  They do the same function as the rsa_encrypt/decrypt 
 * except that they are used to RSA encrypt/decrypt a single value and not a packet.
 */
int rsa_encrypt_key(const unsigned char *inkey, unsigned long inlen,
                    unsigned char *outkey, unsigned long *outlen,
                    prng_state *prng, int wprng, rsa_key *key)
{
   unsigned char rsa_in[4096], rsa_out[4096];
   unsigned long x, y, rsa_size;
   int err;

   _ARGCHK(inkey != NULL);
   _ARGCHK(outkey != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);
   
   /* only allow keys from 64 to 256 bits */
   if (inlen < 8 || inlen > 32) {
      return CRYPT_INVALID_ARG;
   }

   /* are the parameters valid? */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err; 
   }

   /* rsa_pad the symmetric key */
   y = (unsigned long)sizeof(rsa_in); 
   if ((err = rsa_pad(inkey, inlen, rsa_in, &y, wprng, prng)) != CRYPT_OK) {
      return CRYPT_ERROR;
   }
   
   /* rsa encrypt it */
   rsa_size = (unsigned long)sizeof(rsa_out);
   if ((err = rsa_exptmod(rsa_in, y, rsa_out, &rsa_size, PK_PUBLIC, key)) != CRYPT_OK) {
      return CRYPT_ERROR;
   }

   /* check size */
   if (*outlen < (PACKET_SIZE+4+rsa_size)) { 
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* now lets make the header */
   y = PACKET_SIZE;
   
   /* store the size of the RSA value */
   STORE32L(rsa_size, (outkey+y));
   y += 4;

   /* store the rsa value */
   for (x = 0; x < rsa_size; x++, y++) {
       outkey[y] = rsa_out[x];
   }

   /* store header */
   packet_store_header(outkey, PACKET_SECT_RSA, PACKET_SUB_ENC_KEY);

#ifdef CLEAN_STACK
   /* clean up */
   zeromem(rsa_in, sizeof(rsa_in));
   zeromem(rsa_out, sizeof(rsa_out));
#endif
   *outlen = y;
   return CRYPT_OK;
}

int rsa_decrypt_key(const unsigned char *in, unsigned long inlen,
                          unsigned char *outkey, unsigned long *keylen, 
                          rsa_key *key)
{
   unsigned char sym_key[MAXBLOCKSIZE], rsa_out[4096];
   unsigned long x, y, z, i, rsa_size;
   int err;

   _ARGCHK(in != NULL);
   _ARGCHK(outkey != NULL);
   _ARGCHK(keylen != NULL);
   _ARGCHK(key != NULL);

   /* right key type? */
   if (key->type != PK_PRIVATE && key->type != PK_PRIVATE_OPTIMIZED) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   if (inlen < PACKET_SIZE+4) {
      return CRYPT_INVALID_PACKET;
   } else {
      inlen -= PACKET_SIZE+4;
   }

   /* check the header */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_RSA, PACKET_SUB_ENC_KEY)) != CRYPT_OK) {
      return err;
   }

   /* grab length of the rsa key */
   y = PACKET_SIZE;
   LOAD32L(rsa_size, (in+y));
   if (inlen < rsa_size) {
      return CRYPT_INVALID_PACKET;
   } else {
      inlen -= rsa_size;
   }
   y += 4;

   /* decrypt it */
   x = (unsigned long)sizeof(rsa_out);
   if ((err = rsa_exptmod(in+y, rsa_size, rsa_out, &x, PK_PRIVATE, key)) != CRYPT_OK) {
      return err;
   }
   y += rsa_size;

   /* depad it */
   z = (unsigned long)sizeof(sym_key);
   if ((err = rsa_depad(rsa_out, x, sym_key, &z)) != CRYPT_OK) {
      return err;
   }

   /* check size */
   if (*keylen < z) { 
      return CRYPT_BUFFER_OVERFLOW;
   }

   for (i = 0; i < z; i++) {
     outkey[i] = sym_key[i];
   }
   
#ifdef CLEAN_STACK
   /* clean up */
   zeromem(sym_key, sizeof(sym_key));
   zeromem(rsa_out, sizeof(rsa_out));
#endif
   *keylen = z;
   return CRYPT_OK;
}

int rsa_sign_hash(const unsigned char *in,  unsigned long inlen, 
                        unsigned char *out, unsigned long *outlen, 
                        rsa_key *key)
{
   unsigned long rsa_size, x, y;
   unsigned char rsa_in[4096], rsa_out[4096];
   int err;

   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key != NULL);
   
   /* reject nonsense sizes */
   if (inlen > MAXBLOCKSIZE || inlen < 16) {
      return CRYPT_INVALID_ARG;
   }

   /* type of key? */
   if (key->type != PK_PRIVATE && key->type != PK_PRIVATE_OPTIMIZED) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* pad it */
   x = (unsigned long)sizeof(rsa_out);
   if ((err = rsa_signpad(in, inlen, rsa_out, &x)) != CRYPT_OK) {
      return err;
   }

   /* sign it */
   rsa_size = (unsigned long)sizeof(rsa_in);
   if ((err = rsa_exptmod(rsa_out, x, rsa_in, &rsa_size, PK_PRIVATE, key)) != CRYPT_OK) {
      return err;
   }

   /* check size */
   if (*outlen < (PACKET_SIZE+4+rsa_size)) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* now lets output the message */
   y = PACKET_SIZE;

   /* output the len */
   STORE32L(rsa_size, (out+y));
   y += 4;

   /* store the signature */
   for (x = 0; x < rsa_size; x++, y++) {
       out[y] = rsa_in[x];
   }

   /* store header */
   packet_store_header(out, PACKET_SECT_RSA, PACKET_SUB_SIGNED);

#ifdef CLEAN_STACK
   /* clean up */
   zeromem(rsa_in, sizeof(rsa_in));
   zeromem(rsa_out, sizeof(rsa_out));
#endif
   *outlen = y;
   return CRYPT_OK;
}

int rsa_verify_hash(const unsigned char *sig, unsigned long siglen,
                    const unsigned char *md, int *stat, rsa_key *key)
{
   unsigned long rsa_size, x, y, z;
   unsigned char rsa_in[4096], rsa_out[4096];
   int err;

   _ARGCHK(sig != NULL);
   _ARGCHK(md != NULL);
   _ARGCHK(stat != NULL);
   _ARGCHK(key != NULL);

   /* always be incorrect by default */
   *stat = 0;
   
   if (siglen < PACKET_SIZE+4) {
      return CRYPT_INVALID_PACKET;
   } else {
      siglen -= PACKET_SIZE+4;
   }

   /* verify header */
   if ((err = packet_valid_header((unsigned char *)sig, PACKET_SECT_RSA, PACKET_SUB_SIGNED)) != CRYPT_OK) {
      return err;
   }

   /* get the len */
   y = PACKET_SIZE;
   LOAD32L(rsa_size, (sig+y));
   if (siglen < rsa_size) {
      return CRYPT_INVALID_PACKET;
   } else {
      siglen -= rsa_size;
   }
   y += 4;

   /* exptmod it */
   x = (unsigned long)sizeof(rsa_out);
   if ((err = rsa_exptmod(sig+y, rsa_size, rsa_out, &x, PK_PUBLIC, key)) != CRYPT_OK) {
      return err;
   }
   y += rsa_size;

   /* depad it */
   z = (unsigned long)sizeof(rsa_in);
   if ((err = rsa_signdepad(rsa_out, x, rsa_in, &z)) != CRYPT_OK) {
      return err;
   }

   /* check? */
   if (memcmp(rsa_in, md, (size_t)z) == 0) {
      *stat = 1;
   }

#ifdef CLEAN_STACK
   zeromem(rsa_in, sizeof(rsa_in));
   zeromem(rsa_out, sizeof(rsa_out));
#endif
   return CRYPT_OK;
}

