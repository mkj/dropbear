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

/* this table gives the # of rabin miller trials for a prob of failure lower than 2^-96 */
static const struct {
   int k, t;
} sizes[] = {
{   128,    28 },
{   256,    16 },
{   384,    10 },
{   512,     7 },
{   640,     6 },
{   768,     5 },
{   896,     4 },
{  1024,     4 },
{  1152,     3 },
{  1280,     3 },
{  1408,     3 },
{  1536,     3 },
{  1664,     3 },
{  1792,     2 } };

/* returns # of RM trials required for a given bit size */
int mp_prime_rabin_miller_trials(int size)
{
   int x;

   for (x = 0; x < (int)(sizeof(sizes)/(sizeof(sizes[0]))); x++) {
       if (sizes[x].k == size) {
          return sizes[x].t;
       } else if (sizes[x].k > size) {
          return (x == 0) ? sizes[0].t : sizes[x - 1].t;
       }
   }
   return 1;
}


