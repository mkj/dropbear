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
/* OMAC1 Support by Tom St Denis (for 64 and 128 bit block ciphers only) */
#include "mycrypt.h"

#ifdef OMAC

int omac_file(int cipher, 
              const unsigned char *key, unsigned long keylen,
              const char *filename, 
                    unsigned char *out, unsigned long *outlen)
{
#ifdef NO_FILE
   return CRYPT_NOP;
#else
   int err, x;
   omac_state omac;
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

   if ((err = omac_init(&omac, cipher, key, keylen)) != CRYPT_OK) {
      fclose(in);
      return err;
   }

   do {
      x = fread(buf, 1, sizeof(buf), in);
      if ((err = omac_process(&omac, buf, x)) != CRYPT_OK) {
         fclose(in);
         return err;
      }
   } while (x == sizeof(buf));
   fclose(in);

   if ((err = omac_done(&omac, out, outlen)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif

   return CRYPT_OK;
#endif
}

#endif
