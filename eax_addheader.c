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

/* EAX Implementation by Tom St Denis */
#include "mycrypt.h"

#ifdef EAX_MODE

/* add header (metadata) to the stream */
int eax_addheader(eax_state *eax, const unsigned char *header, unsigned long length)
{
   _ARGCHK(eax    != NULL);
   _ARGCHK(header != NULL);
   return omac_process(&eax->headeromac, header, length);
}

#endif
