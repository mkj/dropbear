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

/* Gets length of DER encoding of num */

int der_length_integer(mp_int *num, unsigned long *outlen)
{
   unsigned long z, len;
   int           leading_zero;

   _ARGCHK(num     != NULL);
   _ARGCHK(outlen  != NULL);

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

