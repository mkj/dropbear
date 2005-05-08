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
  @file crypt_unregister_hash.c
  Unregister a hash, Tom St Denis
*/

/**
  Unregister a hash from the descriptor table
  @param hash   The hash descriptor to remove
  @return CRYPT_OK on success
*/
int unregister_hash(const struct ltc_hash_descriptor *hash)
{
   int x;

   LTC_ARGCHK(hash != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (memcmp(&hash_descriptor[x], hash, sizeof(struct ltc_hash_descriptor)) == 0) {
          hash_descriptor[x].name = NULL;
          return CRYPT_OK;
       }
   }
   return CRYPT_ERROR;
}
