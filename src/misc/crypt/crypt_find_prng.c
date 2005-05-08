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
  @file crypt_find_prng.c
  Find a PRNG, Tom St Denis
*/

/**
   Find a registered PRNG by name
   @param name   The name of the PRNG to look for
   @return >= 0 if found, -1 if not present
*/
int find_prng(const char *name)
{
   int x;
   LTC_ARGCHK(name != NULL);
   for (x = 0; x < TAB_SIZE; x++) {
       if ((prng_descriptor[x].name != NULL) && strcmp(prng_descriptor[x].name, name) == 0) {
          return x;
       }
   }
   return -1;
}

