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

/* OCB Implementation by Tom St Denis */
#include "mycrypt.h"

#ifdef OCB_MODE

int ocb_decrypt(ocb_state *ocb, const unsigned char *ct, unsigned char *pt)
{
   unsigned char Z[MAXBLOCKSIZE], tmp[MAXBLOCKSIZE];
   int err, x;

   _ARGCHK(ocb != NULL);
   _ARGCHK(pt  != NULL);
   _ARGCHK(ct  != NULL);

   /* check if valid cipher */
   if ((err = cipher_is_valid(ocb->cipher)) != CRYPT_OK) {
      return err;
   }
   _ARGCHK(cipher_descriptor[ocb->cipher].ecb_decrypt != NULL);
   
   /* check length */
   if (ocb->block_len != cipher_descriptor[ocb->cipher].block_length) {
      return CRYPT_INVALID_ARG;
   }

   /* Get Z[i] value */
   ocb_shift_xor(ocb, Z);

   /* xor ct in, encrypt, xor Z out */
   for (x = 0; x < ocb->block_len; x++) {
       tmp[x] = ct[x] ^ Z[x];
   }
   cipher_descriptor[ocb->cipher].ecb_decrypt(tmp, pt, &ocb->key);
   for (x = 0; x < ocb->block_len; x++) {
       pt[x] ^= Z[x];
   }

   /* compute checksum */
   for (x = 0; x < ocb->block_len; x++) {
       ocb->checksum[x] ^= pt[x];
   }


#ifdef CLEAN_STACK
   zeromem(Z, sizeof(Z));
   zeromem(tmp, sizeof(tmp));
#endif
   return CRYPT_OK;
}

#endif

