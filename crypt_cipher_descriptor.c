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

struct _cipher_descriptor cipher_descriptor[TAB_SIZE] = {
	/* This is ugly, but OS X's ar seems broken and leaves the 
	 * cipher_descriptor symbol out of the .a if we don't
	 * initialise it here. */
	{NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL},
	{NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL},
	{NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL},
	{NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL},
};
