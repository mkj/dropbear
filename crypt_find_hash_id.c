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

int find_hash_id(unsigned char ID)
{
   int x;
   for (x = 0; x < TAB_SIZE; x++) {
       if (hash_descriptor[x].ID == ID) {
          return (hash_descriptor[x].name == NULL) ? -1 : x;
       }
   }
   return -1;
}
