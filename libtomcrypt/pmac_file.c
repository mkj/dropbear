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

int pmac_file(int cipher, 
              const unsigned char *key, unsigned long keylen,
              const char *filename, 
                    unsigned char *out, unsigned long *outlen)
{
#ifdef NO_FILE
   return CRYPT_NOP;
#else
   int err, x;
   pmac_state pmac;
   FILE *in;
   unsigned char buf[512];


   _ARGCHK(key      != NULL);
   _ARGCHK(filename != NULL);
   _ARGCHK(out      != NULL);
   _ARGCHK(outlen   != NULL);

   in = fopen(filename, "rb");
   if (in == NULL) {
      return CRYPT_FILE_NOTFOUND;
   }

   if ((err = pmac_init(&pmac, cipher, key, keylen)) != CRYPT_OK) {
      fclose(in);
      return err;
   }

   do {
      x = fread(buf, 1, sizeof(buf), in);
      if ((err = pmac_process(&pmac, buf, x)) != CRYPT_OK) {
         fclose(in);
         return err;
      }
   } while (x == sizeof(buf));
   fclose(in);

   if ((err = pmac_done(&pmac, out, outlen)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif

   return CRYPT_OK;
#endif
}

#endif
