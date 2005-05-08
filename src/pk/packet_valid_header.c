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

int packet_valid_header(unsigned char *src, int section, int subsection)
{
   unsigned long ver;

   LTC_ARGCHK(src != NULL);

   /* check version */
   ver = ((unsigned long)src[0]) | ((unsigned long)src[1] << 8U);
   if (CRYPT < ver) {
      return CRYPT_INVALID_PACKET;
   }

   /* check section and subsection */
   if (section != (int)src[2] || subsection != (int)src[3]) {
      return CRYPT_INVALID_PACKET;
   }

   return CRYPT_OK;
}

#endif

 
