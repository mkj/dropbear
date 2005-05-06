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
  @file crypt_register_cipher.c
  Register a cipher, Tom St Denis
*/

/**
   Register a cipher with the descriptor table
   @param cipher   The cipher you wish to register
   @return value >= 0 if successfully added (or already present), -1 if unsuccessful
*/
int register_cipher(const struct ltc_cipher_descriptor *cipher)
{
   int x;

   LTC_ARGCHK(cipher != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x].name != NULL && cipher_descriptor[x].ID == cipher->ID) {
          return x;
       }
   }

   /* find a blank spot */
   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x].name == NULL) {
          XMEMCPY(&cipher_descriptor[x], cipher, sizeof(struct ltc_cipher_descriptor));
          return x;
       }
   }

   /* no spot */
   return -1;
}
