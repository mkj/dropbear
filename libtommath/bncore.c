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

/* Known optimal configurations

 CPU                    /Compiler     /MUL CUTOFF/SQR CUTOFF
-------------------------------------------------------------
 Intel P4               /GCC v3.2     /        70/       108
 AMD Athlon XP          /GCC v3.2     /       109/       127
 Intel Celeron          /GCC v3.2.1   /        97/       127
 Mendocino 366mhz (evil)
 Intel P3 750mhz        /GCC v3.2.1   /        95/       110
 Coppermine (mussel)
 Intel Celeron          /GCC v3.2.1   /        85/       125
 Coppermine 700mhz
 Alpha                  /compaq       /        54/        87
 Compaq C V6.4-014 on Compaq Tru64 UNIX V5.1A (Rev. 1885)
 AlphaServer 1000A 5/300
 morwong
 Pentium classic 75     /GCC v3.2.1   /        73/       127
 plod

*/

/* configured for a AMD XP Thoroughbred core with etc/tune.c */
int     KARATSUBA_MUL_CUTOFF = 109,      /* Min. number of digits before Karatsuba multiplication is used. */
        KARATSUBA_SQR_CUTOFF = 127,      /* Min. number of digits before Karatsuba squaring is used. */
        
        TOOM_MUL_CUTOFF      = 350,      /* no optimal values of these are known yet so set em high */
        TOOM_SQR_CUTOFF      = 400; 
