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

int find_hash(const char *name)
{
   int x;
   _ARGCHK(name != NULL);
   for (x = 0; x < TAB_SIZE; x++) {
       if (hash_descriptor[x].name != NULL && strcmp(hash_descriptor[x].name, name) == 0) {
          return x;
       }
   }
   return -1;
}
