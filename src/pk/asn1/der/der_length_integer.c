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
  @file der_length_integer.c
  ASN.1 DER, get length of encoding, Tom St Denis
*/


#ifdef LTC_DER
/**
  Gets length of DER encoding of num 
  @param num    The mp_int to get the size of 
  @param outlen [out] The length of the DER encoding for the given integer
  @return CRYPT_OK if successful
*/
int der_length_integer(mp_int *num, unsigned long *outlen)
{
   unsigned long z, len;
   int           leading_zero;

   LTC_ARGCHK(num     != NULL);
   LTC_ARGCHK(outlen  != NULL);

   /* we only need a leading zero if the msb of the first byte is one */
   if ((mp_count_bits(num) & 7) == 7 || mp_iszero(num) == MP_YES) {
      leading_zero = 1;
   } else {
      leading_zero = 0;
   }

   /* size for bignum */
   z = len = leading_zero + mp_unsigned_bin_size(num);

   /* we need a 0x02 */
   ++len;

   /* now we need a length */
   if (z < 128) {
      /* short form */
      ++len;
   } else {
      /* long form (relies on z != 0) */
      ++len;

      while (z) {
         ++len;
         z >>= 8;
      }
   }

   *outlen = len; 
   return CRYPT_OK;
}

#endif
