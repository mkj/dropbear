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

/* makes a truly random prime of a given size (bytes),
 * call with bbs = 1 if you want it to be congruent to 3 mod 4 
 *
 * You have to supply a callback which fills in a buffer with random bytes.  "dat" is a parameter you can
 * have passed to the callback (e.g. a state or something).  This function doesn't use "dat" itself
 * so it can be NULL
 *
 * The prime generated will be larger than 2^(8*size).
 */

/* this sole function may hold the key to enslaving all mankind! */
int mp_prime_random(mp_int *a, int t, int size, int bbs, ltm_prime_callback cb, void *dat)
{
   unsigned char *tmp;
   int res, err;

   /* sanity check the input */
   if (size <= 0) {
      return MP_VAL;
   }

   /* we need a buffer of size+1 bytes */
   tmp = XMALLOC(size+1);
   if (tmp == NULL) {
      return MP_MEM;
   }

   /* fix MSB */
   tmp[0] = 1;

   do {
      /* read the bytes */
      if (cb(tmp+1, size, dat) != size) {
         err = MP_VAL;
         goto error;
      }
 
      /* fix the LSB */
      tmp[size] |= (bbs ? 3 : 1);

      /* read it in */
      if ((err = mp_read_unsigned_bin(a, tmp, size+1)) != MP_OKAY) {
         goto error;
      }

      /* is it prime? */
      if ((err = mp_prime_is_prime(a, t, &res)) != MP_OKAY) {
         goto error;
      }
   } while (res == MP_NO);

   err = MP_OKAY;
error:
   XFREE(tmp);
   return err;
}


