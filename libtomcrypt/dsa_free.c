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

#ifdef MDSA

void dsa_free(dsa_key *key)
{
   _ARGCHK(key != NULL);
   mp_clear_multi(&key->g, &key->q, &key->p, &key->x, &key->y, NULL);
}

#endif
