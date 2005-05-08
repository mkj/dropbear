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

#ifdef PACKET

void packet_store_header(unsigned char *dst, int section, int subsection)
{
   LTC_ARGCHK(dst != NULL);

   /* store version number */
   dst[0] = (unsigned char)(CRYPT&255);
   dst[1] = (unsigned char)((CRYPT>>8)&255);

   /* store section and subsection */
   dst[2] = (unsigned char)(section & 255);
   dst[3] = (unsigned char)(subsection & 255);

}

#endif
