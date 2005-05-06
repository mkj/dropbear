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
#include <stdarg.h>
#include "tomcrypt.h"

/**
  @file der_put_multi_integer.c
  ASN.1 DER, store multiple integers, Tom St Denis
*/


#ifdef LTC_DER

/* store multiple mp_ints in DER INTEGER format to the out, will not
 * overflow the length you give it [outlen] and store the number of 
 * bytes used in [outlen] 
 */
/**
  Store multiple mp_int integers one after another
  @param out      [out] The destination for the DER encoded integers
  @param outlen   [in/out] The max size and resulting size of the DER encoded integers
  @param num      The first mp_int to encode
  @param ...      A NULL terminated list of mp_ints to encode
  @return CRYPT_OK if successful
*/
int der_put_multi_integer(unsigned char *out, unsigned long *outlen, 
                  mp_int *num, ...)
{
   va_list        args;
   mp_int        *next;
   unsigned long  wrote, len;
   int            err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* setup va list */
   next  = num;
   len   = *outlen;
   wrote = 0;
   va_start(args, num);

   while (next != NULL) {
        if ((err = der_encode_integer(next, out, outlen)) != CRYPT_OK) {
           va_end(args);
           return err;
        }
        wrote   += *outlen;
        out     += *outlen;
        len     -= *outlen;
        *outlen  = len;
        next     = va_arg(args, mp_int*);
   }
   va_end(args);
   *outlen = wrote;
   return CRYPT_OK;
}

#endif
