/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is library that provides for multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library is designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://math.libtomcrypt.org
 */
#include <tommath.h>

/* init a mp_init and grow it to a given size */
int
mp_init_size (mp_int * a, int size)
{

  /* pad size so there are always extra digits */
  size += (MP_PREC * 2) - (size & (MP_PREC - 1));	
  
  /* alloc mem */
  a->dp = OPT_CAST calloc (sizeof (mp_digit), size);
  if (a->dp == NULL) {
    return MP_MEM;
  }
  a->used = 0;
  a->alloc = size;
  a->sign = MP_ZPOS;

  return MP_OKAY;
}
