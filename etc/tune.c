/* Tune the Karatsuba parameters
 *
 * Tom St Denis, tomstdenis@iahu.ca
 */
#include <tommath.h>
#include <time.h>

/* how many times todo each size mult.  Depends on your computer.  For slow computers
 * this can be low like 5 or 10.  For fast [re: Athlon] should be 25 - 50 or so 
 */
#define TIMES (1UL<<14UL)


#ifndef X86_TIMER

/* generic ISO C timer */
ulong64 __T;
void t_start(void) { __T = clock(); }
ulong64 t_read(void) { return clock() - __T; }

#else
extern void t_start(void);
extern ulong64 t_read(void);
#endif

ulong64 time_mult(int size, int s)
{
  unsigned long     x;
  mp_int  a, b, c;
  ulong64 t1;

  mp_init (&a);
  mp_init (&b);
  mp_init (&c);

  mp_rand (&a, size);
  mp_rand (&b, size);

  if (s == 1) { 
      KARATSUBA_MUL_CUTOFF = size;
  } else {
      KARATSUBA_MUL_CUTOFF = 100000;
  }

  t_start();
  for (x = 0; x < TIMES; x++) {
      mp_mul(&a,&b,&c);
  }
  t1 = t_read();
  mp_clear (&a);
  mp_clear (&b);
  mp_clear (&c);
  return t1;
}

ulong64 time_sqr(int size, int s)
{
  unsigned long     x;
  mp_int  a, b;
  ulong64 t1;

  mp_init (&a);
  mp_init (&b);

  mp_rand (&a, size);

  if (s == 1) { 
      KARATSUBA_SQR_CUTOFF = size;
  } else {
      KARATSUBA_SQR_CUTOFF = 100000;
  }

  t_start();
  for (x = 0; x < TIMES; x++) {
      mp_sqr(&a,&b);
  }
  t1 = t_read();
  mp_clear (&a);
  mp_clear (&b);
  return t1;
}

int
main (void)
{
  ulong64 t1, t2;
  int x, y;

  for (x = 8; ; x += 2) { 
     t1 = time_mult(x, 0);
     t2 = time_mult(x, 1);
     printf("%d: %9llu %9llu, %9llu\n", x, t1, t2, t2 - t1);
     if (t2 < t1) break;
  }
  y = x;

  for (x = 8; ; x += 2) { 
     t1 = time_sqr(x, 0);
     t2 = time_sqr(x, 1);
     printf("%d: %9llu %9llu, %9llu\n", x, t1, t2, t2 - t1);
     if (t2 < t1) break;
  }
  printf("KARATSUBA_MUL_CUTOFF = %d\n", y);
  printf("KARATSUBA_SQR_CUTOFF = %d\n", x);

  return 0;
}
