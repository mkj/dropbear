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

/*  Octet to Integer OS2IP -- Tom St Denis */
#ifdef PKCS_1

int pkcs_1_os2ip(mp_int *n, unsigned char *in, unsigned long inlen)
{
   int err;
   /* read it */
   if ((err = mp_read_unsigned_bin(n, in, inlen)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }
   return CRYPT_OK;
}

#endif /* PKCS_1 */

