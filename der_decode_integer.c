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


/* decodes a DER INTEGER in [in].  You have to tell this function
 * how many bytes are available [inlen].  It will then attempt to 
 * read the INTEGER.  If all goes well it stores the number of bytes
 * read in [inlen] and the number in [num].
 */
int der_decode_integer(const unsigned char *in, unsigned long *inlen, mp_int *num)
{
   unsigned long tmplen, y, z;

   _ARGCHK(num    != NULL);
   _ARGCHK(in     != NULL);
   _ARGCHK(inlen  != NULL);

   /* save copy of max output size */
   tmplen = *inlen;
   *inlen = 0;

   /* min DER INTEGER is 0x02 01 00 == 0 */
   if (tmplen < (1 + 1 + 1)) {
      return CRYPT_INVALID_PACKET;
   }

   /* ok expect 0x02 when we AND with 0011 1111 [3F] */
   if ((*in++ & 0x3F) != 0x02) {
      return CRYPT_INVALID_PACKET;
   }
   ++(*inlen);

   /* now decode the len stuff */
   z = *in++;
   ++(*inlen);

   if ((z & 0x80) == 0x00) {
      /* short form */

      /* will it overflow? */
      if (*inlen + z > tmplen) {
         return CRYPT_INVALID_PACKET;
      }
     
      /* no so read it */
      (*inlen) += z;
      return mpi_to_ltc_error(mp_read_unsigned_bin(num, (unsigned char *)in, z));
   } else {
      /* long form */
      z &= 0x7F;
      
      /* will number of length bytes overflow? (or > 4) */
      if (((*inlen + z) > tmplen) || (z > 4)) {
         return CRYPT_INVALID_PACKET;
      }

      /* now read it in */
      y = 0;
      while (z--) {
         y = ((unsigned long)(*in++)) | (y << 8);
         ++(*inlen);
      }

      /* now will reading y bytes overrun? */
      if ((*inlen + y) > tmplen) {
         return CRYPT_INVALID_PACKET;
      }

      /* no so read it */
      (*inlen) += y;
      return mpi_to_ltc_error(mp_read_unsigned_bin(num, (unsigned char *)in, y));
   }
}
