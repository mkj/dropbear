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

#include "mycrypt.h"

#ifdef MRSA

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

#endif /* MRSA */

