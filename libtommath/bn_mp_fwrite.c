/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://math.libtomcrypt.org
 */
#include <tommath.h>

int mp_fwrite(mp_int *a, int radix, FILE *stream)
{
   char *buf;
   int err, len, x;
   
   len = mp_radix_size(a, radix);
   if (len == 0) {
      return MP_VAL;
   }
   
   buf = malloc(len);
   if (buf == NULL) {
      return MP_MEM;
   }
   
   if ((err = mp_toradix(a, buf, radix)) != MP_OKAY) {
      free(buf);
      return err;
   }
   
   for (x = 0; x < len; x++) {
       if (fputc(buf[x], stream) == EOF) {
          free(buf);
          return MP_VAL;
       }
   }
   
   free(buf);
   return MP_OKAY;
}

