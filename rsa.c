/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://libtomcrypt.org
 */

/* RSA Code by Tom St Denis */
#include "mycrypt.h"

#ifdef MRSA

int rsa_signpad(const unsigned char *in,  unsigned long inlen,
                      unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y;

   _ARGCHK(in     != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

   if (*outlen < (3 * inlen)) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* check inlen */
   if (inlen > MAX_RSA_SIZE/8) {
      return CRYPT_PK_INVALID_SIZE;
   }

   for (y = x = 0; x < inlen; x++)
       out[y++] = (unsigned char)0xFF;
   for (x = 0; x < inlen; x++)
       out[y++] = in[x];
   for (x = 0; x < inlen; x++)
       out[y++] = (unsigned char)0xFF;
   *outlen = 3 * inlen;
   return CRYPT_OK;
}

int rsa_pad(const unsigned char *in,  unsigned long inlen,
                  unsigned char *out, unsigned long *outlen,
                  int wprng, prng_state *prng)
{
   unsigned char buf[3*(MAX_RSA_SIZE/8)];
   unsigned long x;
   int err;

   _ARGCHK(in     != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

   /* is output big enough? */
   if (*outlen < (3 * inlen)) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* get random padding required */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* check inlen */
   if (inlen > (MAX_RSA_SIZE/8)) {
      return CRYPT_PK_INVALID_SIZE;
   }

   if (prng_descriptor[wprng].read(buf, inlen*2-2, prng) != (inlen*2 - 2))  {
       return CRYPT_ERROR_READPRNG;
   }

   /* pad it like a sandwhich
    *
    * Looks like 0xFF R1 M R2 0xFF
    *
    * Where R1/R2 are random and exactly equal to the length of M minus one byte.
    */
   for (x = 0; x < inlen-1; x++) {
       out[x+1] = buf[x];
   }

   for (x = 0; x < inlen; x++) {
       out[x+inlen] = in[x];
   }

   for (x = 0; x < inlen-1; x++) {
       out[x+inlen+inlen] = buf[x+inlen-1];
   }

   /* last and first bytes are 0xFF */
   out[0] = out[inlen+inlen+inlen-1] = (unsigned char)0xFF;

   /* clear up and return */
#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   *outlen = inlen*3;
   return CRYPT_OK;
}

int rsa_signdepad(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen)
{
   unsigned long x;

   _ARGCHK(in     != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

   if (*outlen < inlen/3) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* check padding bytes */
   for (x = 0; x < inlen/3; x++) {
       if (in[x] != (unsigned char)0xFF || in[x+(inlen/3)+(inlen/3)] != (unsigned char)0xFF) {
          return CRYPT_INVALID_PACKET;
       }
   }
   for (x = 0; x < inlen/3; x++) {
       out[x] = in[x+(inlen/3)];
   }
   *outlen = inlen/3;
   return CRYPT_OK;
}

int rsa_depad(const unsigned char *in,  unsigned long inlen,
                    unsigned char *out, unsigned long *outlen)
{
   unsigned long x;

   _ARGCHK(in     != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

   if (*outlen < inlen/3) {
      return CRYPT_BUFFER_OVERFLOW;
   }
   for (x = 0; x < inlen/3; x++) {
       out[x] = in[x+(inlen/3)];
   }
   *outlen = inlen/3;
   return CRYPT_OK;
}

int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key)
{
   unsigned long y, z; 
   int err;

   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);
   _ARGCHK(key    != NULL);
   
   /* can we store the static header?  */
   if (*outlen < (PACKET_SIZE + 1)) {
      return CRYPT_BUFFER_OVERFLOW;
   }   

   /* type valid? */
   if (!(key->type == PK_PRIVATE || key->type == PK_PRIVATE_OPTIMIZED) &&
        (type == PK_PRIVATE || type == PK_PRIVATE_OPTIMIZED)) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* start at offset y=PACKET_SIZE */
   y = PACKET_SIZE;

   /* output key type */
   out[y++] = type;

   /* output modulus */
   OUTPUT_BIGNUM(&key->N, out, y, z);

   /* output public key */
   OUTPUT_BIGNUM(&key->e, out, y, z);

   if (type == PK_PRIVATE || type == PK_PRIVATE_OPTIMIZED) {
      OUTPUT_BIGNUM(&key->d, out, y, z);
   }

   if (type == PK_PRIVATE_OPTIMIZED) {
      OUTPUT_BIGNUM(&key->dQ, out, y, z);
      OUTPUT_BIGNUM(&key->dP, out, y, z);
      OUTPUT_BIGNUM(&key->pQ, out, y, z);
      OUTPUT_BIGNUM(&key->qP, out, y, z);
      OUTPUT_BIGNUM(&key->p, out, y, z);
      OUTPUT_BIGNUM(&key->q, out, y, z);
   }

   /* store packet header */
   packet_store_header(out, PACKET_SECT_RSA, PACKET_SUB_KEY);

   /* copy to the user buffer */
   *outlen = y;

   /* clear stack and return */
   return CRYPT_OK;
}

int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   unsigned long x, y;
   int err;

   _ARGCHK(in  != NULL);
   _ARGCHK(key != NULL);

   /* check length */
   if (inlen < (1+PACKET_SIZE)) {
      return CRYPT_INVALID_PACKET;
   }

   /* test packet header */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_RSA, PACKET_SUB_KEY)) != CRYPT_OK) {
      return err;
   }

   /* init key */
   if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP,
                     &key->pQ, &key->p, &key->q, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* get key type */
   y = PACKET_SIZE;
   key->type = (int)in[y++];

   /* load the modulus  */
   INPUT_BIGNUM(&key->N, in, x, y, inlen);

   /* load public exponent */
   INPUT_BIGNUM(&key->e, in, x, y, inlen);

   /* get private exponent */
   if (key->type == PK_PRIVATE || key->type == PK_PRIVATE_OPTIMIZED) {
      INPUT_BIGNUM(&key->d, in, x, y, inlen);
   }

   /* get CRT private data if required */
   if (key->type == PK_PRIVATE_OPTIMIZED) {
      INPUT_BIGNUM(&key->dQ, in, x, y, inlen);
      INPUT_BIGNUM(&key->dP, in, x, y, inlen);
      INPUT_BIGNUM(&key->pQ, in, x, y, inlen);
      INPUT_BIGNUM(&key->qP, in, x, y, inlen);
      INPUT_BIGNUM(&key->p, in, x, y, inlen);
      INPUT_BIGNUM(&key->q, in, x, y, inlen);
   }

   /* free up ram not required */
   if (key->type != PK_PRIVATE_OPTIMIZED) {
      mp_clear_multi(&key->dQ, &key->dP, &key->pQ, &key->qP, &key->p, &key->q, NULL);
   }
   if (key->type != PK_PRIVATE && key->type != PK_PRIVATE_OPTIMIZED) {
      mp_clear(&key->d);
   }

   return CRYPT_OK;
error:
   mp_clear_multi(&key->d, &key->e, &key->N, &key->dQ, &key->dP,
                  &key->pQ, &key->qP, &key->p, &key->q, NULL);
   return err;
}

#include "rsa_sys.c"

#endif /* RSA */


