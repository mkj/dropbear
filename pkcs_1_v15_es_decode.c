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

/* PKCS #1 v1.5 Encryption Padding -- Tom St Denis */

#ifdef PKCS_1

int pkcs_1_v15_es_decode(const unsigned char *msg,  unsigned long msglen,
                               unsigned long modulus_bitlen,
                               unsigned char *out,  unsigned long outlen,
                               int           *res)
{
   unsigned long x, modulus_bytelen;

   _ARGCHK(msg != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(res != NULL);
   
   /* default to failed */
   *res = 0;

   modulus_bytelen = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

   /* must be at least modulus_bytelen bytes long */
   if (msglen != modulus_bytelen) {
      return CRYPT_INVALID_ARG;
   }

   /* should start with 0x00 0x02 */
   if (msg[0] != 0x00 || msg[1] != 0x02) {
      return CRYPT_OK;
   }
   
   /* skip over PS */
   x = 2 + (modulus_bytelen - outlen - 3);

   /* should be 0x00 */
   if (msg[x++] != 0x00) {
      return CRYPT_OK;
   }

   /* the message is left */
   if (x + outlen > modulus_bytelen) {
      return CRYPT_PK_INVALID_SIZE;
   }
   XMEMCPY(out, msg + x, outlen);
   *res = 1;
   return CRYPT_OK;
}

#endif 

