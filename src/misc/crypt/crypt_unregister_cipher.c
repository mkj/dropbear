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
  @file crypt_unregister_cipher.c
  Unregister a cipher, Tom St Denis
*/

/**
  Unregister a cipher from the descriptor table
  @param cipher   The cipher descriptor to remove
  @return CRYPT_OK on success
*/
int unregister_cipher(const struct ltc_cipher_descriptor *cipher)
{
   int x;

   LTC_ARGCHK(cipher != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (memcmp(&cipher_descriptor[x], cipher, sizeof(struct ltc_cipher_descriptor)) == 0) {
          cipher_descriptor[x].name = NULL;
          cipher_descriptor[x].ID   = 255;
          return CRYPT_OK;
       }
   }
   return CRYPT_ERROR;
}
