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

/* PMAC implementation by Tom St Denis */
#include "mycrypt.h"

#ifdef PMAC

void pmac_shift_xor(pmac_state *pmac)
{
   int x, y;
   y = pmac_ntz(pmac->block_index++);
   for (x = 0; x < pmac->block_len; x++) {
       pmac->Li[x] ^= pmac->Ls[y][x];
   }
}

#endif
