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
  @file pkcs_1_os2ip.c
  Octet to Integer OS2IP, Tom St Denis 
*/
#ifdef PKCS_1

/**
  Read a binary string into an mp_int
  @param n          [out] The mp_int destination
  @param in         The binary string to read
  @param inlen      The length of the binary string
  @return CRYPT_OK if successful
*/
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

