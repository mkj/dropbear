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

int register_cipher(const struct _cipher_descriptor *cipher)
{
   int x;

   _ARGCHK(cipher != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x].name != NULL && cipher_descriptor[x].ID == cipher->ID) {
          return x;
       }
   }

   /* find a blank spot */
   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x].name == NULL) {
          XMEMCPY(&cipher_descriptor[x], cipher, sizeof(struct _cipher_descriptor));
          return x;
       }
   }

   /* no spot */
   return -1;
}
