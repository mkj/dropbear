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

/* return first hash with at least [amount over] digestlen bytes of output */
int find_hash_any(const char *name, int digestlen)
{
   int x, y, z;
   _ARGCHK(name != NULL);

   x = find_hash(name);
   if (x != -1) return x;

   y = MAXBLOCKSIZE+1;
   z = -1;
   for (x = 0; x < TAB_SIZE; x++) {
       if (hash_descriptor[x].name == NULL) {
          continue;
       }
       if ((int)hash_descriptor[x].hashsize >= digestlen && (int)hash_descriptor[x].hashsize < y) {
          z = x;
          y = hash_descriptor[x].hashsize;
       }
   }
   return z;
}
