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

struct _hash_descriptor hash_descriptor[TAB_SIZE] = {
	/* OS X has a broken ar, so we need to initialise. */
	{NULL, 0, 0, 0, NULL, NULL, NULL, NULL},
	{NULL, 0, 0, 0, NULL, NULL, NULL, NULL},
	{NULL, 0, 0, 0, NULL, NULL, NULL, NULL},
	{NULL, 0, 0, 0, NULL, NULL, NULL, NULL},
};
