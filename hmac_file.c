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
/* Submited by Dobes Vandermeer  (dobes@smartt.com) */

#include "mycrypt.h"

/*
    (1) append zeros to the end of K to create a B byte string
        (e.g., if K is of length 20 bytes and B=64, then K will be
         appended with 44 zero bytes 0x00)
    (2) XOR (bitwise exclusive-OR) the B byte string computed in step
        (1) with ipad (ipad = the byte 0x36 repeated B times)
    (3) append the stream of data 'text' to the B byte string resulting
        from step (2)
    (4) apply H to the stream generated in step (3)
    (5) XOR (bitwise exclusive-OR) the B byte string computed in
        step (1) with opad (opad = the byte 0x5C repeated B times.)
    (6) append the H result from step (4) to the B byte string
        resulting from step (5)
    (7) apply H to the stream generated in step (6) and output
        the result
*/

#ifdef HMAC

#define HMAC_BLOCKSIZE hash_descriptor[hash].blocksize

/* hmac_file added by Tom St Denis */
int hmac_file(int hash, const char *fname, 
              const unsigned char *key, unsigned long keylen, 
                    unsigned char *dst, unsigned long *dstlen)
{
#ifdef NO_FILE
    return CRYPT_NOP;
#else
   hmac_state hmac;
   FILE *in;
   unsigned char buf[512];
   size_t x;
   int err;

   _ARGCHK(fname  != NULL);
   _ARGCHK(key    != NULL);
   _ARGCHK(dst    != NULL);
   _ARGCHK(dstlen != NULL);
   
   if((err = hash_is_valid(hash)) != CRYPT_OK) {
       return err;
   }

   if ((err = hmac_init(&hmac, hash, key, keylen)) != CRYPT_OK) {
       return err;
   }

   in = fopen(fname, "rb");
   if (in == NULL) {
      return CRYPT_FILE_NOTFOUND;
   }

   /* process the file contents */
   do {
      x = fread(buf, 1, sizeof(buf), in);
      if ((err = hmac_process(&hmac, buf, (unsigned long)x)) != CRYPT_OK) {
         /* we don't trap this error since we're already returning an error! */
         fclose(in);
         return err;
      }
   } while (x == sizeof(buf));

   if (fclose(in) != 0) {
      return CRYPT_ERROR;
   }

   /* get final hmac */
   if ((err = hmac_done(&hmac, dst, dstlen)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK
   /* clear memory */
   zeromem(buf, sizeof(buf));
#endif   
   return CRYPT_OK;
#endif
}

#endif

