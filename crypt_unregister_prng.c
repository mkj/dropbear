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

int unregister_prng(const struct _prng_descriptor *prng)
{
   int x;

   _ARGCHK(prng != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (memcmp(&prng_descriptor[x], prng, sizeof(struct _prng_descriptor)) != 0) {
          prng_descriptor[x].name = NULL;
          return CRYPT_OK;
       }
   }
   return CRYPT_ERROR;
}
