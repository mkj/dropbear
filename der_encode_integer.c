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

/* Exports a positive bignum as DER format (upto 2^32 bytes in size) */
int der_encode_integer(mp_int *num, unsigned char *out, unsigned long *outlen)
{  
   unsigned long tmplen, x, y, z;
   int           err, leading_zero;

   _ARGCHK(num    != NULL);
   _ARGCHK(out    != NULL);
   _ARGCHK(outlen != NULL);

   /* find out how big this will be */
   if ((err = der_length_integer(num, &tmplen)) != CRYPT_OK) {
      return err;
   }

   if (*outlen < tmplen) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* we only need a leading zero if the msb of the first byte is one */
   if ((mp_count_bits(num) & 7) == 7 || mp_iszero(num) == MP_YES) {
      leading_zero = 1;
   } else {
      leading_zero = 0;
   }

   /* get length of num in bytes (plus 1 since we force the msbyte to zero) */
   y = mp_unsigned_bin_size(num) + leading_zero;

   /* now store initial data */
   *out++ = 0x02;
   if (y < 128) {
      /* short form */
      *out++ = (unsigned char)y;
   } else {
      /* long form (relies on y != 0) */

      /* get length of length... ;-) */
      x = y;
      z = 0;
      while (x) {
         ++z;
         x >>= 8;
      }
      
      /* store length of length */
      *out++ = 0x80 | ((unsigned char)z);

      /* now store length */
      
      /* first shift length up so msbyte != 0 */
      x = y;
      while ((x & 0xFF000000) == 0) {
          x <<= 8;
      }

      /* now store length */
      while (z--) {
         *out++ = (unsigned char)((x >> 24) & 0xFF);
         x <<= 8;
      }
   }

   /* now store msbyte of zero if num is non-zero */
   if (leading_zero) {
      *out++ = 0x00;
   }

   /* if it's not zero store it as big endian */
   if (mp_iszero(num) == MP_NO) {
      /* now store the mpint */
      if ((err = mp_to_unsigned_bin(num, out)) != MP_OKAY) {
          return mpi_to_ltc_error(err);
      }
   }

   /* we good */
   *outlen = tmplen; 
   return CRYPT_OK;
}
