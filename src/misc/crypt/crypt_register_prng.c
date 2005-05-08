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
  @file crypt_register_prng.c
  Register a PRNG, Tom St Denis
*/
  
/**
   Register a PRNG with the descriptor table
   @param prng   The PRNG you wish to register
   @return value >= 0 if successfully added (or already present), -1 if unsuccessful
*/
int register_prng(const struct ltc_prng_descriptor *prng)
{
   int x;

   LTC_ARGCHK(prng != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (memcmp(&prng_descriptor[x], prng, sizeof(struct ltc_prng_descriptor)) == 0) {
          return x;
       }
   }

   /* find a blank spot */
   for (x = 0; x < TAB_SIZE; x++) {
       if (prng_descriptor[x].name == NULL) {
          XMEMCPY(&prng_descriptor[x], prng, sizeof(struct ltc_prng_descriptor));
          return x;
       }
   }

   /* no spot */
   return -1;
}
