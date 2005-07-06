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
  @file der_encode_integer.c
  ASN.1 DER, encode an integer, Tom St Denis
*/


#ifdef LTC_DER

/* Exports a positive bignum as DER format (upto 2^32 bytes in size) */
/**
  Store a mp_int integer
  @param num      The first mp_int to encode
  @param out      [out] The destination for the DER encoded integers
  @param outlen   [in/out] The max size and resulting size of the DER encoded integers
  @return CRYPT_OK if successful
*/
int der_encode_integer(mp_int *num, unsigned char *out, unsigned long *outlen)
{  
   unsigned long tmplen, y;
   int           err, leading_zero;

   LTC_ARGCHK(num    != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* find out how big this will be */
   if ((err = der_length_integer(num, &tmplen)) != CRYPT_OK) {
      return err;
   }

   if (*outlen < tmplen) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (mp_cmp_d(num, 0) != MP_LT) {
      /* we only need a leading zero if the msb of the first byte is one */
      if ((mp_count_bits(num) & 7) == 0 || mp_iszero(num) == MP_YES) {
         leading_zero = 1;
      } else {
         leading_zero = 0;
      }

      /* get length of num in bytes (plus 1 since we force the msbyte to zero) */
      y = mp_unsigned_bin_size(num) + leading_zero;
   } else {
      leading_zero = 0;
      y            = mp_count_bits(num);
      y            = y + (8 - (y & 7));
      y            = y >> 3;

   }

   /* now store initial data */
   *out++ = 0x02;
   if (y < 128) {
      /* short form */
      *out++ = (unsigned char)y;
   } else if (y < 256) {
      *out++ = 0x81;
      *out++ = y;
   } else if (y < 65536UL) {
      *out++ = 0x82;
      *out++ = (y>>8)&255;
      *out++ = y;
   } else if (y < 16777216UL) {
      *out++ = 0x83;
      *out++ = (y>>16)&255;
      *out++ = (y>>8)&255;
      *out++ = y;
   } else {
      return CRYPT_INVALID_ARG;
   }

   /* now store msbyte of zero if num is non-zero */
   if (leading_zero) {
      *out++ = 0x00;
   }

   /* if it's not zero store it as big endian */
   if (mp_cmp_d(num, 0) == MP_GT) {
      /* now store the mpint */
      if ((err = mp_to_unsigned_bin(num, out)) != MP_OKAY) {
          return mpi_to_ltc_error(err);
      }
   } else if (mp_iszero(num) != MP_YES) {
      mp_int tmp;
      /* negative */
      if (mp_init(&tmp) != MP_OKAY) {
         return CRYPT_MEM;
      }

      /* 2^roundup and subtract */
      y = mp_count_bits(num);
      y = y + (8 - (y & 7));
      if (mp_2expt(&tmp, y) != MP_OKAY || mp_add(&tmp, num, &tmp) != MP_OKAY) {
         mp_clear(&tmp);
         return CRYPT_MEM;
      }

      if ((err = mp_to_unsigned_bin(&tmp, out)) != MP_OKAY) {
         mp_clear(&tmp);
         return mpi_to_ltc_error(err);
      }
      mp_clear(&tmp);
   }

   /* we good */
   *outlen = tmplen; 
   return CRYPT_OK;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/asn1/der/integer/der_encode_integer.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2005/05/16 15:08:11 $ */
