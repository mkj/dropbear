/* Tune the Karatsuba parameters
 *
 * Tom St Denis, tomstdenis@iahu.ca
 */
#include <tommath.h>
#include <time.h>

/* how many times todo each size mult.  Depends on your computer.  For slow computers
 * this can be low like 5 or 10.  For fast [re: Athlon] should be 25 - 50 or so 
 */
#define TIMES 50


#ifndef X86_TIMER

/* generic ISO C timer */
ulong64 __T;
void t_start(void) { __T = clock(); }
ulong64 t_read(void) { return clock() - __T; }

#else
extern void t_start(void);
extern ulong64 t_read(void);
#endif

ulong64
time_mult (int max)
{
  int     x, y;
  mp_int  a, b, c;

  mp_init (&a);
  mp_init (&b);
  mp_init (&c);

  t_start();
  for (x = 32; x <= max; x += 4) {
    mp_rand (&a, x);
    mp_rand (&b, x);
    for (y = 0; y < TIMES; y++) {
      mp_mul (&a, &b, &c);
    }
  }
  mp_clear (&a);
  mp_clear (&b);
  mp_clear (&c);
  return t_read();
}

ulong64
time_sqr (int max)
{
  int     x, y;
  mp_int  a, b;

  mp_init (&a);
  mp_init (&b);

  t_start();
  for (x = 32; x <= max; x += 4) {
    mp_rand (&a, x);
    for (y = 0; y < TIMES; y++) {
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
  int     best_kmult, best_tmult, best_ksquare, best_tsquare, counter;
  ulong64 best, ti;
  FILE   *log;

  best_kmult = best_ksquare = best_tmult = best_tsquare = 0;
  /* tune multiplication first */
  
  /* effectively turn TOOM off */
  TOOM_SQR_CUTOFF = TOOM_MUL_CUTOFF = 100000;
    
  log = fopen ("mult.log", "w");
  best = -1;
  counter = 16;
  for (KARATSUBA_MUL_CUTOFF = 8; KARATSUBA_MUL_CUTOFF <= 200; KARATSUBA_MUL_CUTOFF++) {
    ti = time_mult (300);
    printf ("%4d : %9llu            \r", KARATSUBA_MUL_CUTOFF, ti);
    fprintf (log, "%d, %llu\n", KARATSUBA_MUL_CUTOFF, ti);
    fflush (stdout);
    if (ti < best) {
      printf ("New best: %llu, %d         \r", ti, KARATSUBA_MUL_CUTOFF);
      best = ti;
      best_kmult = KARATSUBA_MUL_CUTOFF;
      counter = 16;
    } else if (--counter == 0) {
       printf("No better found in 16 trials.\n");
       break;
    }
  }
  fclose (log);
  printf("Karatsuba Multiplier Cutoff (KARATSUBA_MUL_CUTOFF) == %d\n", best_kmult);
  
  /* tune squaring */
  log = fopen ("sqr.log", "w");
  best = -1;
  counter = 16;
  for (KARATSUBA_SQR_CUTOFF = 8; KARATSUBA_SQR_CUTOFF <= 200; KARATSUBA_SQR_CUTOFF++) {
    ti = time_sqr (300);
    printf ("%4d : %9llu             \r", KARATSUBA_SQR_CUTOFF, ti);
    fprintf (log, "%d, %llu\n", KARATSUBA_SQR_CUTOFF, ti);
    fflush (stdout);
    if (ti < best) {
      printf ("New best: %llu, %d         \r", ti, KARATSUBA_SQR_CUTOFF);
      best = ti;
      best_ksquare = KARATSUBA_SQR_CUTOFF;
      counter = 16;
    } else if (--counter == 0) {
       printf("No better found in 16 trials.\n");
       break;
    }
  }
  fclose (log);
  printf("Karatsuba Squaring Cutoff (KARATSUBA_SQR_CUTOFF) == %d\n", best_ksquare);
  
  KARATSUBA_MUL_CUTOFF = best_kmult;
  KARATSUBA_SQR_CUTOFF = best_ksquare;
    
  /* tune TOOM mult */
  counter = 16;
  log = fopen ("tmult.log", "w");
  best = -1;
  for (TOOM_MUL_CUTOFF = best_kmult*5; TOOM_MUL_CUTOFF <= 800; TOOM_MUL_CUTOFF++) {
    ti = time_mult (1200);
    printf ("%4d : %9llu          \r", TOOM_MUL_CUTOFF, ti);
    fprintf (log, "%d, %llu\n", TOOM_MUL_CUTOFF, ti);
    fflush (stdout);
    if (ti < best) {
      printf ("New best: %llu, %d         \r", ti, TOOM_MUL_CUTOFF);
      best = ti;
      best_tmult = TOOM_MUL_CUTOFF;
      counter = 16;
    } else if (--counter == 0) {
       printf("No better found in 16 trials.\n");
       break;
    }
  }
  fclose (log);   
  printf("Toom-Cook Multiplier Cutoff (TOOM_MUL_CUTOFF) == %d\n", best_tmult);
  
  /* tune TOOM sqr */
  log = fopen ("tsqr.log", "w");
  best = -1;
  counter = 16;
  for (TOOM_SQR_CUTOFF = best_ksquare*3; TOOM_SQR_CUTOFF <= 800; TOOM_SQR_CUTOFF++) {
    ti = time_sqr (1200);
    printf ("%4d : %9llu           \r", TOOM_SQR_CUTOFF, ti);
    fprintf (log, "%d, %llu\n", TOOM_SQR_CUTOFF, ti);
    fflush (stdout);
    if (ti < best) {
      printf ("New best: %llu, %d         \r", ti, TOOM_SQR_CUTOFF);
      best = ti;
      best_tsquare = TOOM_SQR_CUTOFF;
      counter = 16;
    } else if (--counter == 0) {
       printf("No better found in 16 trials.\n");
       break;
    }
  }
  fclose (log);   
  printf("Toom-Cook Squaring Cutoff (TOOM_SQR_CUTOFF) == %d\n", best_tsquare);


  return 0;
}
