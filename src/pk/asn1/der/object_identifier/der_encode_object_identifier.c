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
  @file der_encode_object_identifier.c
  ASN.1 DER, Encode Object Identifier, Tom St Denis
*/

#ifdef LTC_DER
/**
  Encode an OID
  @param words   The words to encode  (upto 32-bits each)
  @param nwords  The number of words in the OID
  @param out     [out] Destination of OID data
  @param outlen  [in/out] The max and resulting size of the OID
  @return CRYPT_OK if successful
*/
int der_encode_object_identifier(unsigned long *words, unsigned long  nwords,
                                 unsigned char *out,   unsigned long *outlen)
{
   unsigned long i, x, y, z, t, mask;
   int           err;

   LTC_ARGCHK(words  != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* check length */
   if ((err = der_length_object_identifier(words, nwords, &x)) != CRYPT_OK) {
      return err;
   }
   if (x > *outlen) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* compute length to store OID data */
   z = 1;
   for (y = 2; y < nwords; y++) {
       t = der_object_identifier_bits(words[y]);
       z += t/7 + ((t%7) ? 1 : 0);
   }

   /* store header + length */
   x = 0; 
   out[x++] = 0x06;
   if (z < 128) {
      out[x++] = z;
   } else if (z < 256) {
      out[x++] = 0x81;
      out[x++] = z;
   } else if (z < 65536UL) {
      out[x++] = 0x82;
      out[x++] = (z>>8)&255;
      out[x++] = z&255;
   } else {
      return CRYPT_INVALID_ARG;
   }

   /* store first byte */
   out[x++] = words[0] * 40 + words[1];   
   
    for (i = 2; i < nwords; i++) {
        /* store 7 bit words in little endian */
        t    = words[i] & 0xFFFFFFFF;
        if (t) {
           y    = x;
           mask = 0;
           while (t) {
               out[x++] = (t & 0x7F) | mask;
               t    >>= 7;
               mask  |= 0x80;  /* upper bit is set on all but the last byte */
           }
           /* now swap bytes y...x-1 */
           z = x - 1;
           while (y < z) {
               t = out[y]; out[y] = out[z]; out[z] = t;
               ++y; 
               --z;
           }
       } else {
          /* zero word */
          out[x++] = 0x00;
       }
   }

   *outlen = x;
   return CRYPT_OK;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/asn1/der/object_identifier/der_encode_object_identifier.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2005/05/16 15:08:11 $ */
