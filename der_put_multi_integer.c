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
#include <stdarg.h>
#include "mycrypt.h"

/* store multiple mp_ints in DER INTEGER format to the dst, will not
 * overflow the length you give it [outlen] and store the number of 
 * bytes used in [outlen] 
 */
int der_put_multi_integer(unsigned char *dst, unsigned long *outlen, 
                  mp_int *num, ...)
{
   va_list        args;
   mp_int        *next;
   unsigned long  wrote, len;
   int            err;

   _ARGCHK(dst    != NULL);
   _ARGCHK(outlen != NULL);

   /* setup va list */
   next  = num;
   len   = *outlen;
   wrote = 0;
   va_start(args, num);

   while (next != NULL) {
        if ((err = der_encode_integer(next, dst, outlen)) != CRYPT_OK) {
           va_end(args);
           return err;
        }
        wrote   += *outlen;
        dst     += *outlen;
        len     -= *outlen;
        *outlen  = len;
        next     = va_arg(args, mp_int*);
   }
   va_end(args);
   *outlen = wrote;
   return CRYPT_OK;
}
