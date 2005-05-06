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
  @file crypt_cipher_is_valid.c
  Determine if cipher is valid, Tom St Denis
*/

/*
   Test if a cipher index is valid
   @param idx   The index of the cipher to search for
   @return CRYPT_OK if valid
*/
int cipher_is_valid(int idx)
{
   if (idx < 0 || idx >= TAB_SIZE || cipher_descriptor[idx].name == NULL) {
      return CRYPT_INVALID_CIPHER;
   }
   return CRYPT_OK;
}
