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

/* idea from Wayne Scott */
int find_cipher_any(const char *name, int blocklen, int keylen)
{
   int x;

   _ARGCHK(name != NULL);

   x = find_cipher(name);
   if (x != -1) return x;

   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x].name == NULL) {
          continue;
       }
       if (blocklen <= (int)cipher_descriptor[x].block_length && keylen <= (int)cipher_descriptor[x].max_key_length) {
          return x;
       }
   }
   return -1;
}
