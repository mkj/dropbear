/* Tune the Karatsuba parameters
 *
 * Tom St Denis, tomstdenis@iahu.ca
 */
#include <tommath.h>
#include <time.h>

#ifndef X86_TIMER

/* generic ISO C timer */
unsigned long long __T;
void t_start(void) { __T = clock(); }
unsigned long long t_read(void) { return clock() - __T; }

#else
extern void t_start(void);
extern unsigned long long t_read(void);
#endif

unsigned long long
time_mult (void)
{
  int     x, y;
  mp_int  a, b, c;

  mp_init (&a);
  mp_init (&b);
  mp_init (&c);

  t_start();
  for (x = 32; x <= 288; x += 4) {
    mp_rand (&a, x);
    mp_rand (&b, x);
    for (y = 0; y < 100; y++) {
      mp_mul (&a, &b, &c);
    }
  }
  mp_clear (&a);
  mp_clear (&b);
  mp_clear (&c);
  return t_read();
}

unsigned long long
time_sqr (void)
{
  int     x, y;
  mp_int  a, b;

  mp_init (&a);
  mp_init (&b);

  t_start();
  for (x = 32; x <= 288; x += 4) {
    mp_rand (&a, x);
    for (y = 0; y < 100; y++) {
      mp_sqr (&a, &b);
    }
  }
  mp_clear (&a);
  mp_clear (&b);
  return t_read();
}

int
main (void)
{
  int     best_mult, best_square;
  unsigned long long best, ti;
  FILE   *log;

  best_mult = best_square = 0;
  /* tune multiplication first */
  log = fopen ("mult.log", "w");
  best = -1;
  for (KARATSUBA_MUL_CUTOFF = 8; KARATSUBA_MUL_CUTOFF <= 200; KARATSUBA_MUL_CUTOFF++) {
    ti = time_mult ();
    printf ("%4d : %9llu\r", KARATSUBA_MUL_CUTOFF, ti);
    fprintf (log, "%d, %llu\n", KARATSUBA_MUL_CUTOFF, ti);
    fflush (stdout);
    if (ti < best) {
      printf ("New best: %llu, %d         \n", ti, KARATSUBA_MUL_CUTOFF);
      best = ti;
      best_mult = KARATSUBA_MUL_CUTOFF;
    }
  }
  fclose (log);
  /* tune squaring */
  log = fopen ("sqr.log", "w");
  best = -1;
  for (KARATSUBA_SQR_CUTOFF = 8; KARATSUBA_SQR_CUTOFF <= 200; KARATSUBA_SQR_CUTOFF++) {
    ti = time_sqr ();
    printf ("%4d : %9llu\r", KARATSUBA_SQR_CUTOFF, ti);
    fprintf (log, "%d, %llu\n", KARATSUBA_SQR_CUTOFF, ti);
    fflush (stdout);
    if (ti < best) {
      printf ("New best: %llu, %d         \n", ti, KARATSUBA_SQR_CUTOFF);
      best = ti;
      best_square = KARATSUBA_SQR_CUTOFF;
    }
  }
  fclose (log);

  printf
    ("\n\n\nKaratsuba Multiplier Cutoff: %d\nKaratsuba Squaring Cutoff: %d\n",
     best_mult, best_square);

  return 0;
}
