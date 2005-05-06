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
#include "tomcrypt.h"

/**
  @file rsa_export.c
  Export RSA PKCS keys, Tom St Denis
*/  

#ifdef MRSA

/**
    This will export either an RSAPublicKey or RSAPrivateKey [defined in PKCS #1 v2.1] 
    @param out       [out] Destination of the packet
    @param outlen    [in/out] The max size and resulting size of the packet
    @param type      The type of exported key (PK_PRIVATE or PK_PUBLIC)
    @param key       The RSA key to export
    @return CRYPT_OK if successful
*/    
int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key)
{
   int err, x;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* type valid? */
   if (!(key->type == PK_PRIVATE) && (type == PK_PRIVATE)) {
      return CRYPT_PK_INVALID_TYPE;
   }
   if (*outlen < 4) {
      return CRYPT_BUFFER_OVERFLOW;
   }
  
   /* Mental Note: push space for the header 0x30 0x82 LL LL (LL = length of packet EXcluding 4 bytes) 
    * we assume LL > 255 which is true since the smallest RSA key has a 128-byte modulus (1024-bit)
    */
   *outlen -= 4;

   if (type == PK_PRIVATE) {
      /* private key */
      mp_int zero;

      /* first INTEGER == 0 to signify two-prime RSA */
      if ((err = mp_init(&zero)) != MP_OKAY) {
         return mpi_to_ltc_error(err);
      }
 
      /* output is 
            Version, n, e, d, p, q, d mod (p-1), d mod (q - 1), 1/q mod p
       */
      if ((err = der_put_multi_integer(
                          out+4, outlen, &zero, &key->N, &key->e,
                          &key->d, &key->p, &key->q, &key->dP,
                          &key->dQ, &key->qP, NULL)) != CRYPT_OK) {
         mp_clear(&zero);
         return err;
      }
 
      /* clear zero and return */
      mp_clear(&zero);
   } else {
      /* public key */
      if ((err = der_put_multi_integer(out+4, outlen, &key->N, &key->e, NULL)) != CRYPT_OK) {
         return err;
      }
   }

   /* store the header */
   out[0] = 0x30;
   if (*outlen < 256) {
      /* shift the output up one byte if the header is only 3 bytes */
      for (x = 0; x < *outlen; x++) {
          out[x+3] = out[x+4];
      }
      out[1] = 0x81;
      out[2] = (*outlen & 255);
      *outlen += 3;
   } else {
      out[1] = 0x82;
      out[2] = (*outlen >> 8) & 255;
      out[3] = (*outlen & 255);
      *outlen += 4;
   }
   return err;
}

#endif /* MRSA */

