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

/* Known optimal configurations

 CPU                    /Compiler     /MUL CUTOFF/SQR CUTOFF
-------------------------------------------------------------
 Intel P4               /GCC v3.2     /        81/       110
 AMD Athlon XP          /GCC v3.2     /       109/       127

*/

/* configured for a AMD XP Thoroughbred core with etc/tune.c */
int     KARATSUBA_MUL_CUTOFF = 109,      /* Min. number of digits before Karatsuba multiplication is used. */
        KARATSUBA_SQR_CUTOFF = 127;      /* Min. number of digits before Karatsuba squaring is used. */
