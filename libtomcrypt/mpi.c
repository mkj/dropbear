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
 * Tom St Denis, tomstdenis@iahu.ca, http://libtommath.iahu.ca
 */
#include <mycrypt.h>

/* chars used in radix conversions */
static const char *s_rmap = 
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

#undef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#undef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))

#ifdef DEBUG

/* timing data */
#ifdef TIMER_X86
extern ulong64 gettsc(void);
#else
ulong64 gettsc(void) { return clock(); }
#endif

/* structure to hold timing data */
struct {
   char *func;
   ulong64 start, end, tot;
} timings[1000000];

/* structure to hold consolidated timing data */
struct _functime { 
   char *func;
   ulong64 tot;
} functime[1000];

static char *_funcs[1000];
int _ifuncs, _itims;

#define REGFUNC(name) int __IX = _itims++; _funcs[_ifuncs++] = name; timings[__IX].func = name; timings[__IX].start = gettsc();
#define DECFUNC()     timings[__IX].end = gettsc(); --_ifuncs;
#define VERIFY(val)   _verify(val, #val, __LINE__);

/* sort the consolidated timings */
int qsort_helper(const void *A, const void *B)
{
   struct _functime *a, *b;
   
   a = (struct _functime *)A;
   b = (struct _functime *)B;
   
   if (a->tot > b->tot) return -1;
   if (a->tot < b->tot) return 1;
   return 0;
}

/* reset debugging information */
void reset_timings(void)
{
   _ifuncs = _itims = 0;
}   

/* dump the timing data */
void dump_timings(void)
{
   int x, y;
   ulong64 total;
   
   /* first for every find the total time */
   printf("Phase I  ... Finding totals (%d samples)...\n", _itims);
   for (x = 0; x < _itims; x++) {
       timings[x].tot = timings[x].end - timings[x].start;
   }
   
   /* now subtract the time for each function where nested functions occured */
   printf("Phase II ... Finding dependencies...\n");
   for (x = 0; x < _itims-1; x++) {
       for (y = x+1; y < _itims && timings[y].start <= timings[x].end; y++) {
           timings[x].tot -= timings[y].tot;
           if (timings[x].tot > ((ulong64)1 << (ulong64)40)) {
              timings[x].tot = 0;
           }
       }
   }
   
   /* now consolidate all the entries */
   printf("Phase III... Consolidation...\n");
   
   memset(&functime, 0, sizeof(functime));
   total = 0;
   for (x = 0; x < _itims; x++) {
       if (strcmp(timings[x].func, "_verify")) 
          total += timings[x].tot;
       
       /* try to find this entry */
       for (y = 0; functime[y].func != NULL; y++) {
           if (strcmp(timings[x].func, functime[y].func) == 0) {
              break;
           }
       }
       
       if (functime[y].func == NULL) {
          /* new entry */
          functime[y].func = timings[x].func;
          functime[y].tot  = timings[x].tot;
       } else { 
          functime[y].tot  += timings[x].tot;
       }
   }
   
   for (x = 0; functime[x].func != NULL; x++);
   
   /* sort and dump */
   qsort(&functime, x, sizeof(functime[0]), &qsort_helper);
   
   for (x = 0; functime[x].func != NULL; x++) {
      if (functime[x].tot > 0 && strcmp(functime[x].func, "_verify") != 0) {
         printf("%30s: %20llu (%3llu.%03llu %%)\n", functime[x].func, functime[x].tot, (functime[x].tot * (ulong64)100) / total, ((functime[x].tot * (ulong64)100000) / total) % (ulong64)1000);
      }
   }
}   

static void _verify(mp_int *a, char *name, int line)
{
  int n, y;
  static const char *err[] = { "Null DP", "alloc < used", "digits above used" };
  
  REGFUNC("_verify");

  /* dp null ? */
  y = 0;
  if (a->dp == NULL) goto error;
  
  /* used should be <= alloc */
  ++y;
  if (a->alloc < a->used) goto error;
  
  /* digits above used should be zero */
  ++y;
  for (n = a->used; n < a->alloc; n++) {
     if (a->dp[n]) goto error;
  }

  /* ok */
  DECFUNC();
  return;
error:
  printf("Error (%s) with variable {%s} on line %d\n", err[y], name, line);
  for (n = _ifuncs - 1; n >= 0; n--) {
      if (_funcs[n] != NULL) {
         printf("> %s\n", _funcs[n]);
      }
  }
  printf("\n");
  exit(0);
}

#else /* don't use DEBUG stuff so these macros are blank */

#define REGFUNC(name)
#define DECFUNC()
#define VERIFY(val)

#endif 

/* init a new bigint */
int mp_init(mp_int *a)
{
    REGFUNC("mp_init");
    
    /* allocate ram required and clear it */
    a->dp = XCALLOC(sizeof(mp_digit), MP_PREC);
    if (a->dp == NULL) {
       DECFUNC();
       return MP_MEM;
    }
    
    /* set the used to zero, allocated digit to the default precision 
     * and sign to positive */
    a->used  = 0;
    a->alloc = MP_PREC;
    a->sign  = MP_ZPOS;
    
    VERIFY(a);
    DECFUNC();
    return MP_OKAY;
}

/* clear one (frees)  */
void mp_clear(mp_int *a)
{
   REGFUNC("mp_clear");
   if (a->dp != NULL) {
      VERIFY(a);
      
      /* first zero the digits */
      memset(a->dp, 0, sizeof(mp_digit) * a->used);
      
      /* free ram */
      XFREE(a->dp);
      
      /* reset members to make debugging easier */
      a->dp = NULL;
      a->alloc = a->used = 0;
   }
   DECFUNC();
}

void mp_exch(mp_int *a, mp_int *b)
{
   mp_int t;
  
   REGFUNC("mp_exch");
   VERIFY(a);
   VERIFY(b);
   t = *a; *a = *b; *b = t;
   DECFUNC();
}   

/* grow as required */
static int mp_grow(mp_int *a, int size)
{
   int i, n;
   
   REGFUNC("mp_grow");
   VERIFY(a);
   
   /* if the alloc size is smaller alloc more ram */
   if (a->alloc < size) {
      size += (MP_PREC*2) - (size & (MP_PREC-1));           /* ensure there are always at least 16 digits extra on top */
     
      a->dp = XREALLOC(a->dp, sizeof(mp_digit)*size);
      if (a->dp == NULL) {
         DECFUNC();
         return MP_MEM;
      }

      n = a->alloc;
      a->alloc = size;
      for (i = n; i < a->alloc; i++) {
          a->dp[i] = 0;
      }
   }
   DECFUNC();
   return MP_OKAY;
}

/* shrink a bignum */
int mp_shrink(mp_int *a)
{
   REGFUNC("mp_shrink");
   VERIFY(a);
   if (a->alloc != a->used) {
      if ((a->dp = XREALLOC(a->dp, sizeof(mp_digit) * a->used)) == NULL) {
         DECFUNC();
         return MP_MEM;
      }
      a->alloc = a->used;
   }
   DECFUNC();
   return MP_OKAY;
}

/* trim unused digits */
static void mp_clamp(mp_int *a)
{
   REGFUNC("mp_clamp");
   VERIFY(a);
   while (a->used > 0 && a->dp[a->used-1] == 0) --(a->used);
   if (a->used == 0) {
      a->sign = MP_ZPOS;
   }      
   DECFUNC();
}   
   
/* set to zero */
void mp_zero(mp_int *a)
{
   REGFUNC("mp_zero");
   VERIFY(a);
   a->sign = MP_ZPOS;
   a->used = 0;
   memset(a->dp, 0, sizeof(mp_digit) * a->alloc);
   DECFUNC();
}

/* set to a digit */
void mp_set(mp_int *a, mp_digit b)
{
   REGFUNC("mp_set");
   VERIFY(a);
   mp_zero(a);
   a->dp[0] = b & MP_MASK;
   a->used  = (a->dp[0] != 0) ? 1: 0;
   DECFUNC();
}

/* set a 32-bit const */
int mp_set_int(mp_int *a, unsigned long b)
{
   int x, res;
   
   REGFUNC("mp_set_int");
   VERIFY(a);
   mp_zero(a);

   /* set four bits at a time, simplest solution to the what if DIGIT_BIT==7 case */
   for (x = 0; x < 8; x++) {
   
      /* shift the number up four bits */
      if ((res = mp_mul_2d(a, 4, a)) != MP_OKAY) {
         DECFUNC();
         return res;
      }
      
      /* OR in the top four bits of the source */      
      a->dp[0] |= (b>>28)&15;
      
      /* shift the source up to the next four bits */
      b <<= 4;
      
      /* ensure that digits are not clamped off */      
      a->used += 32/DIGIT_BIT + 1;
   }
   
   mp_clamp(a);
   DECFUNC();
   return MP_OKAY;
}   

/* init a mp_init and grow it to a given size */
int mp_init_size(mp_int *a, int size)
{
   REGFUNC("mp_init_size");
   
   /* pad up so there are at least 16 zero digits */
   size += (MP_PREC*2) - (size & (MP_PREC-1));           /* ensure there are always at least 16 digits extra on top */
   a->dp = XCALLOC(sizeof(mp_digit), size);
   if (a->dp == NULL) {
      DECFUNC();
      return MP_MEM;
   }
   a->used  = 0;
   a->alloc = size;
   a->sign  = MP_ZPOS;

   DECFUNC();
   return MP_OKAY;
}

/* copy, b = a */
int mp_copy(mp_int *a, mp_int *b)
{
   int res, n;
   
   REGFUNC("mp_copy");
   VERIFY(a);
   VERIFY(b);

   /* if dst == src do nothing */
   if (a == b || a->dp == b->dp) {
      DECFUNC();
      return MP_OKAY;
   }
   
   /* grow dest */
   if ((res = mp_grow(b, a->used)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   
   /* zero b and copy the parameters over */
   b->used = a->used;
   b->sign = a->sign;
   
   /* copy all the digits */
   for (n = 0; n < a->used; n++) {
       b->dp[n] = a->dp[n];
   }
   
   /* clear high digits */
   for (n = b->used; n < b->alloc; n++) {
       b->dp[n] = 0;
   }
   DECFUNC();
   return MP_OKAY;
}

/* creates "a" then copies b into it */
int mp_init_copy(mp_int *a, mp_int *b)
{
  int res;
  
  REGFUNC("mp_init_copy");
  VERIFY(b);
  if ((res = mp_init(a)) != MP_OKAY) {
     DECFUNC();
     return res;
  }
  res = mp_copy(b, a);
  DECFUNC();
  return res;
}

/* b = |a| */
int mp_abs(mp_int *a, mp_int *b)
{
   int res;
   REGFUNC("mp_abs");
   VERIFY(a);
   VERIFY(b);
   if ((res = mp_copy(a, b)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   b->sign = MP_ZPOS;
   DECFUNC();
   return MP_OKAY;
}

/* b = -a */
int mp_neg(mp_int *a, mp_int *b)
{
   int res;
   REGFUNC("mp_neg");
   VERIFY(a);
   VERIFY(b);
   if ((res = mp_copy(a, b)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   b->sign = (a->sign == MP_ZPOS) ? MP_NEG : MP_ZPOS;
   DECFUNC();
   return MP_OKAY;
}

/* compare maginitude of two ints (unsigned) */
int mp_cmp_mag(mp_int *a, mp_int *b) 
{
   int n;

   REGFUNC("mp_cmp_mag");
   VERIFY(a);
   VERIFY(b);
   
   /* compare based on # of non-zero digits */   
   if (a->used > b->used) {
      DECFUNC();
      return MP_GT;
   } else if (a->used < b->used) {
      DECFUNC();
      return MP_LT;
   }
   
   /* compare based on digits  */
   for (n = a->used - 1; n >= 0; n--) {
       if (a->dp[n] > b->dp[n]) {
          DECFUNC();
          return MP_GT;
       } else if (a->dp[n] < b->dp[n]) {
          DECFUNC();
          return MP_LT;
       }
   }
   DECFUNC();
   return MP_EQ;
}

/* compare two ints (signed)*/
int mp_cmp(mp_int *a, mp_int *b)
{
   int res;
   REGFUNC("mp_cmp");
   VERIFY(a);
   VERIFY(b);
   /* compare based on sign */
   if (a->sign == MP_NEG && b->sign == MP_ZPOS) {
      DECFUNC();
      return MP_LT;
   } else if (a->sign == MP_ZPOS && b->sign == MP_NEG) {
      DECFUNC();
      return MP_GT;
   }
   res = mp_cmp_mag(a, b);
   DECFUNC();
   return res;
}

/* compare a digit */
int mp_cmp_d(mp_int *a, mp_digit b)
{
   REGFUNC("mp_cmp_d");
   VERIFY(a);
   
   if (a->sign == MP_NEG) {
      DECFUNC();
      return MP_LT;
   }
   
   if (a->used > 1) {
      DECFUNC();
      return MP_GT;
   }
   
   if (a->dp[0] > b) {
      DECFUNC();
      return MP_GT;
   } else if (a->dp[0] < b) {
      DECFUNC();
      return MP_LT;
   } else {
      DECFUNC();
      return MP_EQ;
   }
}

/* shift right a certain amount of digits */
void mp_rshd(mp_int *a, int b)
{
   int x;
   
   REGFUNC("mp_rshd");
   VERIFY(a);
   
   /* if b <= 0 then ignore it */
   if (b <= 0) {
      DECFUNC();
      return;
   }
   
   /* if b > used then simply zero it and return */
   if (a->used < b) {
      mp_zero(a);
      DECFUNC();
      return;
   }
   
   /* shift the digits down */
   for (x = 0; x < (a->used - b); x++) {
       a->dp[x] = a->dp[x + b];
   }
   
   /* zero the top digits */
   for (; x < a->used; x++) {
       a->dp[x] = 0;
   }
   mp_clamp(a);
   DECFUNC();
}

/* shift left a certain amount of digits */
int mp_lshd(mp_int *a, int b)
{
   int x, res;
   
   REGFUNC("mp_lshd");
   VERIFY(a);
   
   /* if its less than zero return */
   if (b <= 0) {
      DECFUNC();
      return MP_OKAY;
   }
      
   /* grow to fit the new digits */
   if ((res = mp_grow(a, a->used + b)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   
   /* increment the used by the shift amount than copy upwards */
   a->used += b;
   for (x = a->used-1; x >= b; x--) {
       a->dp[x] = a->dp[x - b];
   }
   
   /* zero the lower digits */
   for (x = 0; x < b; x++) {
       a->dp[x] = 0;
   }
   mp_clamp(a);
   DECFUNC();
   return MP_OKAY;
}

/* calc a value mod 2^b */
int mp_mod_2d(mp_int *a, int b, mp_int *c)
{
   int x, res;
   
   REGFUNC("mp_mod_2d");
   VERIFY(a);
   VERIFY(c);
   
   /* if b is <= 0 then zero the int */
   if (b <= 0) {
      mp_zero(c);
      DECFUNC();
      return MP_OKAY;
   }
   
   /* if the modulus is larger than the value than return */
   if (b > (int)(a->used * DIGIT_BIT)) {
      res = mp_copy(a, c);
      DECFUNC();
      return res;      
   }
   
   /* copy */
   if ((res = mp_copy(a, c)) != MP_OKAY) {
      DECFUNC();
      return res;
   }

   /* zero digits above the last digit of the modulus */
   for (x = (b/DIGIT_BIT) + ((b % DIGIT_BIT) == 0 ? 0 : 1); x < c->used; x++) {
       c->dp[x] = 0;
   }
   /* clear the digit that is not completely outside/inside the modulus */
   c->dp[b/DIGIT_BIT] &= (mp_digit)((((mp_digit)1)<<(((mp_digit)b) % DIGIT_BIT)) - ((mp_digit)1));
   mp_clamp(c);
   DECFUNC();
   return MP_OKAY;
}
   
/* shift right by a certain bit count (store quotient in c, remainder in d) */
int  mp_div_2d(mp_int *a, int b, mp_int *c, mp_int *d)
{
   mp_digit D, r, rr;
   int x, res;
   mp_int t;
   
   REGFUNC("mp_div_2d");
   VERIFY(a);
   VERIFY(c);
   if (d != NULL) { VERIFY(d); }
   
   /* if the shift count is <= 0 then we do no work */
   if (b <= 0) {
      res = mp_copy(a, c);
      if (d != NULL) { mp_zero(d); }
      DECFUNC();
      return res;
   }      
   
   if ((res = mp_init(&t)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   
   /* get the remainder */
   if (d != NULL) {
      if ((res = mp_mod_2d(a, b, &t)) != MP_OKAY) {
         mp_clear(&t);
         DECFUNC();
         return res;
      }
   }
   
   /* copy */
   if ((res = mp_copy(a, c)) != MP_OKAY) {
      mp_clear(&t);
      DECFUNC();
      return res;
   }
   
   /* shift by as many digits in the bit count */
   mp_rshd(c, b/DIGIT_BIT);
   
   /* shift any bit count < DIGIT_BIT */
   D = (mp_digit)(b % DIGIT_BIT);
   if (D != 0) {
      r = 0;
      for (x = c->used - 1; x >= 0; x--) {
          /* get the lower  bits of this word in a temp */
          rr = c->dp[x] & ((mp_digit)((1U<<D)-1U));
          
          /* shift the current word and mix in the carry bits from the previous word */
          c->dp[x] = (c->dp[x] >> D) | (r << (DIGIT_BIT-D));
          
          /* set the carry to the carry bits of the current word found above */
          r  = rr;
      }
   }
   mp_clamp(c);
   res = MP_OKAY;
   if (d != NULL) {
      mp_exch(&t, d);
   }
   mp_clear(&t);
   DECFUNC();
   return MP_OKAY;
}

/* shift left by a certain bit count */
int mp_mul_2d(mp_int *a, int b, mp_int *c)
{
   mp_digit d, r, rr;
   int x, res;
   
   REGFUNC("mp_mul_2d");
   VERIFY(a);
   VERIFY(c);
   
   /* copy */
   if ((res = mp_copy(a, c)) != MP_OKAY) {
      DECFUNC();
      return res;
   }

   if ((res = mp_grow(c, c->used + b/DIGIT_BIT + 1)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   
   /* shift by as many digits in the bit count */
   if ((res = mp_lshd(c, b/DIGIT_BIT)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   c->used = c->alloc;
   
   /* shift any bit count < DIGIT_BIT */
   d = (mp_digit)(b % DIGIT_BIT);   
   if (d != 0) {
      r = 0;
      for (x = 0; x < c->used; x++) {
          /* get the higher bits of the current word */
          rr = (c->dp[x] >> (DIGIT_BIT - d)) & ((mp_digit)((1U<<d)-1U));
          
          /* shift the current word and OR in the carry */
          c->dp[x] = ((c->dp[x] << d) | r) & MP_MASK;
          
          /* set the carry to the carry bits of the current word */
          r  = rr;
      }
   }
   mp_clamp(c);
   DECFUNC();
   return MP_OKAY;
}   

/* b = a/2 */
int mp_div_2(mp_int *a, mp_int *b)
{
   mp_digit r, rr;
   int x, res;
   
   REGFUNC("mp_div_2");
   VERIFY(a);
   VERIFY(b);

   /* copy */
   if ((res = mp_copy(a, b)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   
   r = 0;
   for (x = b->used - 1; x >= 0; x--) {
       rr = b->dp[x] & 1;
       b->dp[x] = (b->dp[x] >> 1) | (r << (DIGIT_BIT-1));
       r  = rr;
   }
   mp_clamp(b);
   DECFUNC();
   return MP_OKAY;
}

/* b = a*2 */
int mp_mul_2(mp_int *a, mp_int *b)
{
   mp_digit r, rr;
   int x, res;
   
   REGFUNC("mp_mul_2");
   VERIFY(a);
   VERIFY(b);
   
   /* copy */
   if ((res = mp_copy(a, b)) != MP_OKAY) {
      DECFUNC();
      return res;
   }

   if ((res = mp_grow(b, b->used + 1)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   ++b->used;
   
   /* shift any bit count < DIGIT_BIT */
   r = 0;
   for (x = 0; x < b->used; x++) {
       rr = (b->dp[x] >> (DIGIT_BIT - 1)) & 1;
       b->dp[x] = ((b->dp[x] << 1) | r) & MP_MASK;
       r  = rr;
   }
   mp_clamp(b);
   DECFUNC();
   return MP_OKAY;
}

/* low level addition, based on HAC pp.594, Algorithm 14.7 */
static int s_mp_add(mp_int *a, mp_int *b, mp_int *c)
{
   mp_int *x;
   int olduse, res, min, max, i;
   mp_digit u;
   
   REGFUNC("s_mp_add");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   /* find sizes, we let |a| <= |b| which means we have to sort
    * them.  "x" will point to the input with the most digits
    */
   if (a->used > b->used) {
      min = b->used;
      max = a->used;
      x   = a;
   } else if (a->used < b->used) {
      min = a->used;
      max = b->used;
      x   = b;
   } else {
      min = max = a->used;
      x = NULL;
   }
   
   /* init result */
   if (c->alloc < max+1) {
      if ((res = mp_grow(c, max+1)) != MP_OKAY) {
         DECFUNC();
         return res;
      }
   }
 
   olduse  = c->used;
   c->used = max + 1;

   /* add digits from lower part */
   
   /* set the carry to zero */
   u = 0;
   for (i = 0; i < min; i++) {
       /* Compute the sum at one digit, T[i] = A[i] + B[i] + U */   
       c->dp[i] = a->dp[i] + b->dp[i] + u;
       
       /* U = carry bit of T[i] */       
       u = (c->dp[i] >> DIGIT_BIT) & 1;
       
       /* take away carry bit from T[i] */
       c->dp[i] &= MP_MASK;
   }
   
   /* now copy higher words if any, that is in A+B if A or B has more digits add those in */
   if (min != max) {
      for (; i < max; i++) { 
         /* T[i] = X[i] + U */
         c->dp[i] = x->dp[i] + u;
         
         /* U = carry bit of T[i] */
         u = (c->dp[i] >> DIGIT_BIT) & 1;
         
         /* take away carry bit from T[i] */
         c->dp[i] &= MP_MASK;
      }
   }
   
   /* add carry */
   c->dp[i] = u;
   
   /* clear digits above used (since we may not have grown result above) */
   for (i = c->used; i < olduse; i++) {
      c->dp[i] = 0;
   }
   
   mp_clamp(c);
   DECFUNC();
   return MP_OKAY;       
}

/* low level subtraction (assumes a > b), HAC pp.595 Algorithm 14.9 */
static int s_mp_sub(mp_int *a, mp_int *b, mp_int *c)
{
   int olduse, res, min, max, i;
   mp_digit u;
   
   REGFUNC("s_mp_sub");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   /* find sizes */
   min = b->used;
   max = a->used;
   
   /* init result */
   if (c->alloc < max) {
      if ((res = mp_grow(c, max)) != MP_OKAY) {
         DECFUNC();
         return res;
      }
   }
   olduse  = c->used;
   c->used = max;
   
   /* sub digits from lower part */
   
   /* set carry to zero */
   u = 0;
   for (i = 0; i < min; i++) {
       /* T[i] = A[i] - B[i] - U */
       c->dp[i] = a->dp[i] - (b->dp[i] + u);
       
       /* U = carry bit of T[i] */
       u = (c->dp[i] >> DIGIT_BIT) & 1;
       
       /* Clear carry from T[i] */
       c->dp[i] &= MP_MASK;
   }
   
   /* now copy higher words if any, e.g. if A has more digits than B  */
   if (min != max) {
      for (; i < max; i++) { 
         /* T[i] = A[i] - U */
         c->dp[i] = a->dp[i] - u;

         /* U = carry bit of T[i] */
         u = (c->dp[i] >> DIGIT_BIT) & 1;

         /* Clear carry from T[i] */
         c->dp[i] &= MP_MASK;
      }
   }
   
   /* clear digits above used (since we may not have grown result above) */
   for (i = c->used; i < olduse; i++) {
      c->dp[i] = 0;
   }

   mp_clamp(c);
   DECFUNC();
   return MP_OKAY;       
}

/* low level multiplication */
#define s_mp_mul(a, b, c) s_mp_mul_digs(a, b, c, (a)->used + (b)->used + 1)

/* Fast (comba) multiplier
 *
 * This is the fast column-array [comba] multiplier.  It is designed to compute
 * the columns of the product first then handle the carries afterwards.  This 
 * has the effect of making the nested loops that compute the columns very
 * simple and schedulable on super-scalar processors.
 *
 */
static int fast_s_mp_mul_digs(mp_int *a, mp_int *b, mp_int *c, int digs)
{
   int olduse, res, pa, ix;
   mp_word W[512];
   
   REGFUNC("fast_s_mp_mul_digs");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   if (c->alloc < digs) {
      if ((res = mp_grow(c, digs)) != MP_OKAY) {
         DECFUNC();
         return res;
      }
   }
   
   /* clear temp buf (the columns) */
   memset(W, 0, sizeof(mp_word) * digs);
   
   /* calculate the columns */
   pa = a->used;
   for (ix = 0; ix < pa; ix++) {
   
       /* this multiplier has been modified to allow you to control how many digits 
        * of output are produced.  So at most we want to make upto "digs" digits
        * of output
        */
       
       
       /* this adds products to distinct columns (at ix+iy) of W
        * note that each step through the loop is not dependent on
        * the previous which means the compiler can easily unroll
        * the loop without scheduling problems
        */
       {
          register mp_digit tmpx, *tmpy;
          register mp_word  *_W;
          register int      iy, pb;
          
          /* alias for the the word on the left e.g. A[ix] * A[iy] */
          tmpx = a->dp[ix];
          
          /* alias for the right side */
          tmpy = b->dp;

          /* alias for the columns, each step through the loop adds a new
             term to each column 
           */
          _W   = W + ix;
          
          /* the number of digits is limited by their placement.  E.g. 
             we avoid multiplying digits that will end up above the # of
             digits of precision requested
           */
          pb = MIN(b->used, digs - ix);
          
          for (iy = 0; iy < pb; iy++) {
              *_W++ += ((mp_word)tmpx) * ((mp_word)*tmpy++); 
          }
       }

   }
   
   /* setup dest */
   olduse  = c->used;
   c->used = digs;

   
   /* At this point W[] contains the sums of each column.  To get the
    * correct result we must take the extra bits from each column and
    * carry them down
    *
    * Note that while this adds extra code to the multiplier it saves time
    * since the carry propagation is removed from the above nested loop.
    * This has the effect of reducing the work from N*(N+N*c)==N^2 + c*N^2 to
    * N^2 + N*c where c is the cost of the shifting.  On very small numbers
    * this is slower but on most cryptographic size numbers it is faster.
    */
    
   for (ix = 1; ix < digs; ix++) {
       W[ix]       += (W[ix-1] >> ((mp_word)DIGIT_BIT));
       c->dp[ix-1] = (mp_digit)(W[ix-1] & ((mp_word)MP_MASK));
   }
   c->dp[digs-1]   = (mp_digit)(W[digs-1] & ((mp_word)MP_MASK));
   
   /* clear unused */
   for (; ix < olduse; ix++) {
      c->dp[ix] = 0;
   }
  
   mp_clamp(c);
   DECFUNC();
   return MP_OKAY;
}

/* multiplies |a| * |b| and only computes upto digs digits of result 
 * HAC pp. 595, Algorithm 14.12  Modified so you can control how many digits of 
 * output are created.  
 */
static int s_mp_mul_digs(mp_int *a, mp_int *b, mp_int *c, int digs)
{
   mp_int t;
   int res, pa, pb, ix, iy;
   mp_digit u;
   mp_word r;
   mp_digit tmpx, *tmpt, *tmpy;
   
   REGFUNC("s_mp_mul_digs");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   /* can we use the fast multiplier? 
    *
    * The fast multiplier can be used if the output will have less than 
    * 512 digits and the number of digits won't affect carry propagation
    */
   if ((digs < 512) && digs < (1<<( (CHAR_BIT*sizeof(mp_word)) - (2*DIGIT_BIT)))) {
      res = fast_s_mp_mul_digs(a,b,c,digs);
      DECFUNC();
      return res;
   }  
   
   if ((res = mp_init_size(&t, digs)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   t.used = digs;
   
   /* compute the digits of the product directly */
   pa = a->used;
   for (ix = 0; ix < pa; ix++) {
       /* set the carry to zero */
       u = 0;
       
       /* limit ourselves to making digs digits of output */
       pb = MIN(b->used, digs - ix);
              
       /* setup some aliases */
       tmpx = a->dp[ix];
       tmpt = &(t.dp[ix]);
       tmpy = b->dp;
       
       /* compute the columns of the output and propagate the carry */
       for (iy = 0; iy < pb; iy++) {
           /* compute the column as a mp_word */
           r       = ((mp_word)*tmpt) + ((mp_word)tmpx) * ((mp_word)*tmpy++) + ((mp_word)u);
           
           /* the new column is the lower part of the result */           
           *tmpt++ = (mp_digit)(r & ((mp_word)MP_MASK));
           
           /* get the carry word from the result */
           u       = (mp_digit)(r >> ((mp_word)DIGIT_BIT));
       }
       if (ix+iy<digs)
          *tmpt = u;
   }
   
   mp_clamp(&t);
   mp_exch(&t, c);

   mp_clear(&t);
   DECFUNC();
   return MP_OKAY;
}

/* this is a modified version of fast_s_mp_mul_digs that only produces
 * output digits *above* digs.  See the comments for fast_s_mp_mul_digs 
 * to see how it works.
 *
 * This is used in the Barrett reduction since for one of the multiplications
 * only the higher digits were needed.  This essentially halves the work.
 */
static int fast_s_mp_mul_high_digs(mp_int *a, mp_int *b, mp_int *c, int digs)
{
   int oldused, newused, res, pa, pb, ix;
   mp_word W[512];
   
   REGFUNC("fast_s_mp_mul_high_digs");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   newused = a->used + b->used + 1;
   if (c->alloc < newused) {
      if ((res = mp_grow(c, newused)) != MP_OKAY) {
         DECFUNC();
         return res;
      }
   }
   
   /* like the other comba method we compute the columns first */
   pa = a->used;
   pb = b->used;
   memset(&W[digs], 0, (pa + pb + 1 - digs) * sizeof(mp_word));
   for (ix = 0; ix < pa; ix++) {
       {
	      register mp_digit tmpx, *tmpy;
	      register int      iy;
	      register mp_word  *_W;

          /* work todo, that is we only calculate digits that are at "digs" or above  */
          iy   = digs - ix;
          
          /* copy of word on the left of A[ix] * B[iy] */
          tmpx = a->dp[ix];
          
          /* alias for right side */
          tmpy = b->dp + iy;
          
          /* alias for the columns of output.  Offset to be equal to or above the 
           * smallest digit place requested 
           */
          _W   = &(W[digs]);
       
          /* compute column products for digits above the minimum */
          for (; iy < pb; iy++) {
              *_W++ += ((mp_word)tmpx) * ((mp_word)*tmpy++);
          }
       }
   }
   
   /* setup dest */
   oldused = c->used;
   c->used = newused;
   
   /* now convert the array W downto what we need */
   for (ix = digs+1; ix < newused; ix++) {
       W[ix]       += (W[ix-1] >> ((mp_word)DIGIT_BIT));
       c->dp[ix-1] = (mp_digit)(W[ix-1] & ((mp_word)MP_MASK));
   }
   c->dp[(pa+pb+1)-1] = (mp_digit)(W[(pa+pb+1)-1] & ((mp_word)MP_MASK));
   
   for (; ix < oldused; ix++) {
      c->dp[ix] = 0;
   }
   mp_clamp(c);
   DECFUNC();
   return MP_OKAY;
}

/* multiplies |a| * |b| and does not compute the lower digs digits 
 * [meant to get the higher part of the product]
 */
static int s_mp_mul_high_digs(mp_int *a, mp_int *b, mp_int *c, int digs)
{
   mp_int t;
   int res, pa, pb, ix, iy;
   mp_digit u;
   mp_word r;
   mp_digit tmpx, *tmpt, *tmpy;
   
   REGFUNC("s_mp_mul_high_digs");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   /* can we use the fast multiplier? */
   if (((a->used + b->used + 1) < 512) && MAX(a->used, b->used) < (1<<( (CHAR_BIT*sizeof(mp_word)) - (2*DIGIT_BIT)))) {
      res = fast_s_mp_mul_high_digs(a,b,c,digs);
      DECFUNC();
      return res;
   }  

   if ((res = mp_init_size(&t, a->used + b->used + 1)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   t.used = a->used + b->used + 1;
   
   pa = a->used;
   pb = b->used;
   for (ix = 0; ix < pa; ix++) {
       /* clear the carry */
       u = 0;
       
       /* left hand side of A[ix] * B[iy] */
       tmpx = a->dp[ix];
       
       /* alias to the address of where the digits will be stored */       
       tmpt = &(t.dp[digs]);
       
       /* alias for where to read the right hand side from */       
       tmpy = b->dp + (digs - ix);
       
       for (iy = digs - ix; iy < pb; iy++) {
           /* calculate the double precision result */
           r       = ((mp_word)*tmpt) + ((mp_word)tmpx) * ((mp_word)*tmpy++) + ((mp_word)u);
           
           /* get the lower part */
           *tmpt++ = (mp_digit)(r & ((mp_word)MP_MASK));
           
           /* carry the carry */
           u       = (mp_digit)(r >> ((mp_word)DIGIT_BIT));
       }
       *tmpt = u;
   }
   mp_clamp(&t);
   mp_exch(&t, c);
   mp_clear(&t);
   DECFUNC();
   return MP_OKAY;
}

/* fast squaring 
 *
 * This is the comba method where the columns of the product are computed first 
 * then the carries are computed.  This has the effect of making a very simple
 * inner loop that is executed the most
 *
 * W2 represents the outer products and W the inner.  
 *
 * A further optimizations is made because the inner products are of the form
 * "A * B * 2".  The *2 part does not need to be computed until the end which is
 * good because 64-bit shifts are slow!
 *
 *
 */
static int fast_s_mp_sqr(mp_int *a, mp_int *b)
{
   int olduse, newused, res, ix, pa;
   mp_word  W2[512], W[512];
   
   REGFUNC("fast_s_mp_sqr");
   VERIFY(a);
   VERIFY(b);

   pa = a->used;
   newused = pa + pa + 1;
   if (b->alloc < newused) {
      if ((res = mp_grow(b, newused)) != MP_OKAY) {
         DECFUNC();
         return res;
      }
   }   
   
   /* zero temp buffer (columns) */
   memset(W, 0, (pa+pa+1)*sizeof(mp_word));
   memset(W2, 0, (pa+pa+1)*sizeof(mp_word));
   
   for (ix = 0; ix < pa; ix++) {
       /* compute the outer product */
       W2[ix+ix]   += ((mp_word)a->dp[ix]) * ((mp_word)a->dp[ix]);
       
       {
          register mp_digit tmpx, *tmpy;
          register mp_word  *_W;
          register int      iy;
          
          /* copy of left side */
          tmpx = a->dp[ix];
          
          /* alias for right side */
          tmpy = a->dp + (ix + 1);
          
	      _W   = &(W[ix+ix+1]);
	   
	      /* inner products */
          for (iy = ix + 1; iy < pa; iy++) {
	          *_W++ += ((mp_word)tmpx) * ((mp_word)*tmpy++);
          }
       }
   }
   
   /* double first value, since the inner products are half of what they should be */
   W[0] += W[0] + W2[0];
   
   /* setup dest */
   olduse  = b->used;
   b->used = newused;
   
   /* now compute digits */
   for (ix = 1; ix < newused; ix++) {
       /* double/add next digit */
       W[ix]       += W[ix] + W2[ix];

       W[ix]       = W[ix] + (W[ix-1] >> ((mp_word)DIGIT_BIT));
       b->dp[ix-1] = (mp_digit)(W[ix-1] & ((mp_word)MP_MASK));
   }
   b->dp[(newused)-1] = (mp_digit)(W[(newused)-1] & ((mp_word)MP_MASK));
   
   /* clear high */
   for (; ix < olduse; ix++) {
       b->dp[ix] = 0;
   }
   
   /* fix the sign (since we no longer make a fresh temp) */
   b->sign = MP_ZPOS;
   
   mp_clamp(b);
   DECFUNC();
   return MP_OKAY;
}

/* low level squaring, b = a*a, HAC pp.596-597, Algorithm 14.16 */
static int s_mp_sqr(mp_int *a, mp_int *b)
{
   mp_int t;
   int res, ix, iy, pa;
   mp_word  r, u;
   mp_digit tmpx, *tmpt;
   
   REGFUNC("s_mp_sqr");
   VERIFY(a);
   VERIFY(b);
   
   /* can we use the fast multiplier? */  
   if (((a->used * 2 + 1) < 512) && a->used < (1<<( (CHAR_BIT*sizeof(mp_word)) - (2*DIGIT_BIT) - 1))) {
      res = fast_s_mp_sqr(a,b);
      DECFUNC();
      return res;
   }  
   
   pa = a->used;
   if ((res = mp_init_size(&t, pa + pa + 1)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   t.used = pa + pa + 1;
   
   for (ix = 0; ix < pa; ix++) {
       /* first calculate the digit at 2*ix */
       /* calculate double precision result */   
       r           = ((mp_word)t.dp[ix+ix]) + ((mp_word)a->dp[ix]) * ((mp_word)a->dp[ix]);
       
       /* store lower part in result */       
       t.dp[ix+ix] = (mp_digit)(r & ((mp_word)MP_MASK));
       
       /* get the carry */
	   u           = (r >> ((mp_word)DIGIT_BIT));
	   
	   /* left hand side of A[ix] * A[iy] */
	   tmpx = a->dp[ix];
	   
	   /* alias for where to store the results */
	   tmpt = &(t.dp[ix+ix+1]);
	   for (iy = ix + 1; iy < pa; iy++) {
	       /* first calculate the product */
	       r           = ((mp_word)tmpx) * ((mp_word)a->dp[iy]);
	       
	       /* now calculate the double precision result, note we use
	        * addition instead of *2 since its easier to optimize
	        */
	       r           = ((mp_word)*tmpt) + r + r + ((mp_word)u);
	       
	       /* store lower part */
           *tmpt++     = (mp_digit)(r & ((mp_word)MP_MASK));
           
           /* get carry */
    	   u           = (r >> ((mp_word)DIGIT_BIT));
       }
       r           = ((mp_word)*tmpt) + u;
       *tmpt       = (mp_digit)(r & ((mp_word)MP_MASK));
  	   u           = (r >> ((mp_word)DIGIT_BIT));
       /* propagate upwards */
       ++tmpt;
       while (u != ((mp_word)0)) { 
          r                = ((mp_word)*tmpt) + ((mp_word)1);
          *tmpt++          = (mp_digit)(r & ((mp_word)MP_MASK));
          u                = (r >> ((mp_word)DIGIT_BIT));
       }
   }
   
   mp_clamp(&t);
   mp_exch(&t, b);
   mp_clear(&t);
   DECFUNC();
   return MP_OKAY;
}

/* high level addition (handles signs) */
int mp_add(mp_int *a, mp_int *b, mp_int *c)
{
   int sa, sb, res;
 
   REGFUNC("mp_add");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);

   sa = a->sign;
   sb = b->sign;

   /* handle four cases */
   if (sa == MP_ZPOS && sb == MP_ZPOS) {
      /* both positive */
      res = s_mp_add(a, b, c);
      c->sign = MP_ZPOS;
   } else if (sa == MP_ZPOS && sb == MP_NEG) {
      /* a + -b == a - b, but if b>a then we do it as -(b-a) */
      if (mp_cmp_mag(a, b) == MP_LT) {
         res = s_mp_sub(b, a, c);
         c->sign = MP_NEG;
      } else {
         res = s_mp_sub(a, b, c);
         c->sign = MP_ZPOS;
      }
   } else if (sa == MP_NEG && sb == MP_ZPOS) {
      /* -a + b == b - a, but if a>b then we do it as -(a-b) */
      if (mp_cmp_mag(a, b) == MP_GT) {
         res = s_mp_sub(a, b, c);
         c->sign = MP_NEG;
      } else {
         res = s_mp_sub(b, a, c);
         c->sign = MP_ZPOS;
      }
   } else {
      /* -a + -b == -(a + b) */
      res = s_mp_add(a, b, c);
      c->sign = MP_NEG;
   }
   DECFUNC();
   return res;
}

/* high level subtraction (handles signs) */
int mp_sub(mp_int *a, mp_int *b, mp_int *c)
{
   int sa, sb, res;
   
   REGFUNC("mp_sub");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   sa = a->sign;
   sb = b->sign;

   /* handle four cases */
   if (sa == MP_ZPOS && sb == MP_ZPOS) {
      /* both positive, a - b, but if b>a then we do -(b - a) */
      if (mp_cmp_mag(a, b) == MP_LT) {
         /* b>a */
         res = s_mp_sub(b, a, c); 
         c->sign = MP_NEG;
      } else {
         res = s_mp_sub(a, b, c);
         c->sign = MP_ZPOS;
      }
   } else if (sa == MP_ZPOS && sb == MP_NEG) {
      /* a - -b == a + b  */
      res = s_mp_add(a, b, c);
      c->sign = MP_ZPOS;
   } else if (sa == MP_NEG && sb == MP_ZPOS) {
      /* -a - b == -(a + b) */
      res = s_mp_add(a, b, c);
      c->sign = MP_NEG;
   } else {
      /* -a - -b == b - a, but if a>b == -(a - b) */
      if (mp_cmp_mag(a, b) == MP_GT) {
         res = s_mp_sub(a, b, c);
         c->sign = MP_NEG;
      } else {
         res = s_mp_sub(b, a, c);
         c->sign = MP_ZPOS;
      }
   }

   DECFUNC();
   return res;
}

/* c = |a| * |b| using Karatsuba Multiplication */
static int mp_karatsuba_mul(mp_int *a, mp_int *b, mp_int *c)
{
   mp_int x0, x1, y0, y1, t1, t2, x0y0, x1y1;
   int B, err, x;

   REGFUNC("mp_karatsuba_mul");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);

   err = MP_MEM;

   /* min # of digits */
   B = MIN(a->used, b->used);
 
   /* now divide in two */
   B = B/2;

   /* init copy all the temps */
   if (mp_init_size(&x0, B) != MP_OKAY) goto ERR;
   if (mp_init_size(&x1, a->used - B) != MP_OKAY) goto X0;
   if (mp_init_size(&y0, B) != MP_OKAY) goto X1;
   if (mp_init_size(&y1, b->used - B) != MP_OKAY) goto Y0;

   /* init temps */
   if (mp_init(&t1) != MP_OKAY)         goto Y1;
   if (mp_init(&t2) != MP_OKAY)         goto T1;
   if (mp_init(&x0y0) != MP_OKAY)       goto T2;
   if (mp_init(&x1y1) != MP_OKAY)       goto X0Y0;

   /* now shift the digits */
   x0.sign = x1.sign = a->sign;
   y0.sign = y1.sign = b->sign;
   
   x0.used = y0.used = B;
   x1.used = a->used - B;
   y1.used = b->used - B;
   
   for (x = 0; x < B; x++) {
      x0.dp[x] = a->dp[x];
      y0.dp[x] = b->dp[x];
   }
   for (x = B; x < a->used; x++) {
      x1.dp[x-B] = a->dp[x];
   }
   for (x = B; x < b->used; x++) {
      y1.dp[x-B] = b->dp[x];
   }
   
   mp_clamp(&x0);
   mp_clamp(&y0);
   
   /* now calc the products x0y0 and x1y1 */
   if (mp_mul(&x0, &y0, &x0y0) != MP_OKAY) goto X1Y1;             /* x0y0 = x0*y0 */
   if (mp_mul(&x1, &y1, &x1y1) != MP_OKAY) goto X1Y1;             /* x1y1 = x1*y1 */

   /* now calc x1-x0 and y1-y0 */
   if (mp_sub(&x1, &x0, &t1) != MP_OKAY) goto X1Y1;               /* t1 = x1 - x0 */
   if (mp_sub(&y1, &y0, &t2) != MP_OKAY) goto X1Y1;               /* t2 = y1 - y0 */
   if (mp_mul(&t1, &t2, &t1) != MP_OKAY) goto X1Y1;               /* t1 = (x1 - x0) * (y1 - y0) */

   /* add x0y0 */
   if (mp_add(&x0y0, &x1y1, &t2) != MP_OKAY) goto X1Y1;           /* t2 = x0y0 + x1y1 */
   if (mp_sub(&t2, &t1, &t1) != MP_OKAY) goto X1Y1;               /* t1 = x0y0 + x1y1 - (x1-x0)*(y1-y0) */

   /* shift by B */
   if (mp_lshd(&t1, B) != MP_OKAY) goto X1Y1;                     /* t1 = (x0y0 + x1y1 - (x1-x0)*(y1-y0))<<B */
   if (mp_lshd(&x1y1, B*2) != MP_OKAY) goto X1Y1;                 /* x1y1 = x1y1 << 2*B */

   if (mp_add(&x0y0, &t1, &t1) != MP_OKAY) goto X1Y1;             /* t1 = x0y0 + t1 */
   if (mp_add(&t1, &x1y1, c) != MP_OKAY) goto X1Y1;               /* t1 = x0y0 + t1 + x1y1 */

   err = MP_OKAY;

X1Y1: mp_clear(&x1y1);
X0Y0: mp_clear(&x0y0);
T2  : mp_clear(&t2);
T1  : mp_clear(&t1);
Y1  : mp_clear(&y1);
Y0  : mp_clear(&y0);
X1  : mp_clear(&x1);
X0  : mp_clear(&x0);
ERR :
    DECFUNC();
    return err;
}

/* high level multiplication (handles sign) */
int mp_mul(mp_int *a, mp_int *b, mp_int *c)
{
   int res, neg;
   REGFUNC("mp_mul");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   neg = (a->sign == b->sign) ? MP_ZPOS : MP_NEG;
   if (MIN(a->used, b->used) > KARATSUBA_MUL_CUTOFF) {
      res = mp_karatsuba_mul(a, b, c);
   } else {
      res = s_mp_mul(a, b, c);
   }
   c->sign = neg;
   DECFUNC();
   return res;
}

/* Karatsuba squaring, computes b = a*a */
static int mp_karatsuba_sqr(mp_int *a, mp_int *b)
{
   mp_int x0, x1, t1, t2, x0x0, x1x1;
   int B, err, x;
   
   REGFUNC("mp_karatsuba_sqr");
   VERIFY(a);
   VERIFY(b);

   err = MP_MEM;

   /* min # of digits */
   B = a->used;

   /* now divide in two */
   B = B/2;

   /* init copy all the temps */
   if (mp_init_size(&x0, B) != MP_OKAY) goto ERR;
   if (mp_init_size(&x1, a->used - B) != MP_OKAY) goto X0;

   /* init temps */
   if (mp_init(&t1) != MP_OKAY)         goto X1;
   if (mp_init(&t2) != MP_OKAY)         goto T1;
   if (mp_init(&x0x0) != MP_OKAY)       goto T2;
   if (mp_init(&x1x1) != MP_OKAY)       goto X0X0;

   /* now shift the digits */
   for (x = 0; x < B; x++) {
       x0.dp[x] = a->dp[x];
   }

   for (x = B; x < a->used; x++) {
       x1.dp[x-B] = a->dp[x];
   }
   
   x0.used = B;
   x1.used = a->used - B;
   
   mp_clamp(&x0);
   
   /* now calc the products x0*x0 and x1*x1 */
   if (mp_sqr(&x0, &x0x0) != MP_OKAY) goto X1X1;                  /* x0x0 = x0*x0 */
   if (mp_sqr(&x1, &x1x1) != MP_OKAY) goto X1X1;                  /* x1x1 = x1*x1 */

   /* now calc x1-x0 and y1-y0 */
   if (mp_sub(&x1, &x0, &t1) != MP_OKAY) goto X1X1;               /* t1 = x1 - x0 */
   if (mp_sqr(&t1, &t1) != MP_OKAY) goto X1X1;                    /* t1 = (x1 - x0) * (y1 - y0) */

   /* add x0y0 */
   if (mp_add(&x0x0, &x1x1, &t2) != MP_OKAY) goto X1X1;           /* t2 = x0y0 + x1y1 */
   if (mp_sub(&t2, &t1, &t1) != MP_OKAY) goto X1X1;               /* t1 = x0y0 + x1y1 - (x1-x0)*(y1-y0) */

   /* shift by B */
   if (mp_lshd(&t1, B) != MP_OKAY) goto X1X1;                     /* t1 = (x0y0 + x1y1 - (x1-x0)*(y1-y0))<<B */
   if (mp_lshd(&x1x1, B*2) != MP_OKAY) goto X1X1;                 /* x1y1 = x1y1 << 2*B */

   if (mp_add(&x0x0, &t1, &t1) != MP_OKAY) goto X1X1;             /* t1 = x0y0 + t1 */
   if (mp_add(&t1, &x1x1, b) != MP_OKAY) goto X1X1;               /* t1 = x0y0 + t1 + x1y1 */

   err = MP_OKAY;
   
X1X1: mp_clear(&x1x1);
X0X0: mp_clear(&x0x0);
T2  : mp_clear(&t2);
T1  : mp_clear(&t1);
X1  : mp_clear(&x1);
X0  : mp_clear(&x0);
ERR :
    DECFUNC();
    return err;
}

/* computes b = a*a */
int mp_sqr(mp_int *a, mp_int *b)
{
   int res;
   REGFUNC("mp_sqr");
   VERIFY(a);
   VERIFY(b);
   if (a->used > KARATSUBA_SQR_CUTOFF) {
      res = mp_karatsuba_sqr(a, b);
   } else {
      res = s_mp_sqr(a, b);
   }
   b->sign = MP_ZPOS;
   DECFUNC();
   return res;
}


/* integer signed division. c*b + d == a [e.g. a/b, c=quotient, d=remainder] 
 * HAC pp.598 Algorithm 14.20
 *
 * Note that the description in HAC is horribly incomplete.  For example, 
 * it doesn't consider the case where digits are removed from 'x' in the inner
 * loop.  It also doesn't consider the case that y has fewer than three digits, etc..
 *
 * The overall algorithm is as described as 14.20 from HAC but fixed to treat these cases.
*/
int mp_div(mp_int *a, mp_int *b, mp_int *c, mp_int *d)
{
   mp_int q, x, y, t1, t2;
   int res, n, t, i, norm, neg;
   
   REGFUNC("mp_div");
   VERIFY(a);
   VERIFY(b);
   if (c != NULL) { VERIFY(c); }
   if (d != NULL) { VERIFY(d); }
   
   /* is divisor zero ? */
   if (mp_iszero(b) == 1) {
      DECFUNC();
      return MP_VAL;
   }
   
   /* if a < b then q=0, r = a */
   if (mp_cmp_mag(a, b) == MP_LT) {
      if (d != NULL) {
           res = mp_copy(a, d);
      } else {
           res = MP_OKAY;
      }
      if (c != NULL) {
         mp_zero(c);
      }
      DECFUNC();
      return res;
   }
 
   if ((res = mp_init_size(&q, a->used + 2)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   q.used = a->used + 2;
   
   if ((res = mp_init(&t1)) != MP_OKAY) {
      goto __Q;
   }
   
   if ((res = mp_init(&t2)) != MP_OKAY) {
      goto __T1;
   }
   
   if ((res = mp_init_copy(&x, a)) != MP_OKAY) {
      goto __T2;
   }

   if ((res = mp_init_copy(&y, b)) != MP_OKAY) {
      goto __X;
   }
   
   /* fix the sign */
   neg = (a->sign == b->sign) ? MP_ZPOS : MP_NEG;
   x.sign = y.sign = MP_ZPOS;
   
   /* normalize both x and y, ensure that y >= b/2, [b == 2^DIGIT_BIT] */
   norm = 0;
   while ((y.dp[y.used-1] & (((mp_digit)1)<<(DIGIT_BIT-1))) == ((mp_digit)0)) {
      ++norm;
      if ((res = mp_mul_2d(&x, 1, &x)) != MP_OKAY) {
         goto __Y;
      }
      if ((res = mp_mul_2d(&y, 1, &y)) != MP_OKAY) {
         goto __Y;
      }
   }
   
   /* note hac does 0 based, so if used==5 then its 0,1,2,3,4, e.g. use 4 */
   n = x.used - 1;
   t = y.used - 1;

   /* step 2. while (x >= y*b^n-t) do { q[n-t] += 1; x -= y*b^{n-t} } */
   if ((res = mp_lshd(&y, n - t)) != MP_OKAY) {                            /* y = y*b^{n-t} */
      goto __Y;
   }
 
   while (mp_cmp(&x, &y) != MP_LT) {
       ++(q.dp[n - t]);
       if ((res = mp_sub(&x, &y, &x)) != MP_OKAY) {
          goto __Y;
       }
   }
   
   /* reset y by shifting it back down */
   mp_rshd(&y, n - t);
   
   /* step 3. for i from n down to (t + 1) */
   for (i = n; i >= (t + 1); i--) {
       if (i > x.alloc) continue;
       
       /* step 3.1 if xi == yt then set q{i-t-1} to b-1, otherwise set q{i-t-1} to (xi*b + x{i-1})/yt */
       if (x.dp[i] == y.dp[t]) {
          q.dp[i - t - 1] = ((1UL<<DIGIT_BIT)-1UL);
       } else {
          mp_word tmp;
          tmp  = ((mp_word)x.dp[i]) << ((mp_word)DIGIT_BIT);
          tmp |= ((mp_word)x.dp[i-1]);
          tmp /= ((mp_word)y.dp[t]);
          if (tmp > (mp_word)MP_MASK) tmp = MP_MASK;
          q.dp[i - t - 1] = (mp_digit)(tmp & (mp_word)(MP_MASK));
       }
       
       /* step 3.2 while (q{i-t-1} * (yt * b + y{t-1})) > xi * b^2 + xi-1 * b + xi-2 do q{i-t-1} -= 1; */
       q.dp[i-t-1] = (q.dp[i-t-1] + 1) & MP_MASK;
       do {
          q.dp[i-t-1] = (q.dp[i-t-1] - 1) & MP_MASK;
          
          /* find left hand */
          mp_zero(&t1);
          t1.dp[0] = (t-1 < 0) ? 0 : y.dp[t-1];
          t1.dp[1] = y.dp[t];
          t1.used = 2;
          if ((res = mp_mul_d(&t1, q.dp[i-t-1], &t1)) != MP_OKAY) {
             goto __Y;
          }
          
          /* find right hand */
          t2.dp[0] = (i - 2 < 0) ? 0 : x.dp[i-2];
          t2.dp[1] = (i - 1 < 0) ? 0 : x.dp[i-1];
          t2.dp[2] = x.dp[i];
          t2.used = 3;
       } while (mp_cmp(&t1, &t2) == MP_GT);
        
       /* step 3.3 x = x - q{i-t-1} * y * b^{i-t-1} */
       if ((res = mp_mul_d(&y, q.dp[i-t-1], &t1)) != MP_OKAY) {
          goto __Y;
       }
       
       if ((res = mp_lshd(&t1, i - t - 1)) != MP_OKAY) {
          goto __Y;
       }
       
       if ((res = mp_sub(&x, &t1, &x)) != MP_OKAY) { 
          goto __Y;
       }
       
       /* step 3.4 if x < 0 then { x = x + y*b^{i-t-1}; q{i-t-1} -= 1; } */
       if (x.sign == MP_NEG) {
          if ((res = mp_copy(&y, &t1)) != MP_OKAY) {
             goto __Y;
          }
          if ((res = mp_lshd(&t1, i-t-1)) != MP_OKAY) {
             goto __Y;
          }
          if ((res = mp_add(&x, &t1, &x)) != MP_OKAY) {
             goto __Y;
          }
          
          q.dp[i-t-1] = (q.dp[i-t-1] - 1UL) & MP_MASK;
       }
    }
    
    /* now q is the quotient and x is the remainder [which we have to normalize] */
    /* get sign before writing to c */
    x.sign = a->sign;
    if (c != NULL) {
       mp_clamp(&q);
       mp_exch(&q, c);
       c->sign = neg;
    }
    
    if (d != NULL) {
       mp_div_2d(&x, norm, &x, NULL);
       mp_clamp(&x);
       mp_exch(&x, d);
    }
        
   res = MP_OKAY;

__Y:   mp_clear(&y);
__X:   mp_clear(&x);
__T2:  mp_clear(&t2);
__T1:  mp_clear(&t1);
__Q:   mp_clear(&q);
   DECFUNC();
   return res;   
}

/* c = a mod b, 0 <= c < b */
int mp_mod(mp_int *a, mp_int *b, mp_int *c)
{
   mp_int t;
   int res;
   
   REGFUNC("mp_mod");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   if ((res = mp_init(&t)) != MP_OKAY) {
      DECFUNC();
      return res;
   }

   if ((res = mp_div(a, b, NULL, &t)) != MP_OKAY) {
      mp_clear(&t);
      DECFUNC();
      return res;
   }
   
   if (t.sign == MP_NEG) {
      res = mp_add(b, &t, c);
   } else {
      res = MP_OKAY;
      mp_exch(&t, c);
   }

   mp_clear(&t);
   DECFUNC();
   return res;
}

/* single digit addition */
int mp_add_d(mp_int *a, mp_digit b, mp_int *c)
{
   mp_int t;
   int res;
   
   REGFUNC("mp_add_d");
   VERIFY(a);
   VERIFY(c);
   
   if ((res = mp_init(&t)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   mp_set(&t, b);
   res = mp_add(a, &t, c);

   mp_clear(&t);
   DECFUNC();
   return res;
}   
   
/* single digit subtraction */
int mp_sub_d(mp_int *a, mp_digit b, mp_int *c)
{
   mp_int t;
   int res;
   
   REGFUNC("mp_sub_d");
   VERIFY(a);
   VERIFY(c);
   
   if ((res = mp_init(&t)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   mp_set(&t, b);
   res = mp_sub(a, &t, c);

   mp_clear(&t);
   DECFUNC();
   return res;
}

/* multiply by a digit */
int mp_mul_d(mp_int *a, mp_digit b, mp_int *c)
{
   int res, pa, ix;
   mp_word  r;
   mp_digit u;
   mp_int   t;
   
   REGFUNC("mp_mul_d");
   VERIFY(a);
   VERIFY(c);
   
   pa = a->used;
   if ((res = mp_init_size(&t, pa + 2)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   t.used = pa + 2;
   
   u = 0;
   for (ix = 0; ix < pa; ix++) {
       r = ((mp_word)u) + ((mp_word)a->dp[ix]) * ((mp_word)b);
       t.dp[ix] = (mp_digit)(r & ((mp_word)MP_MASK));
	   u        = (mp_digit)(r >> ((mp_word)DIGIT_BIT));
   }
   t.dp[ix] = u;
   
   t.sign = a->sign;
   mp_clamp(&t);
   mp_exch(&t, c);
   mp_clear(&t);
   DECFUNC();
   return MP_OKAY;
}

/* single digit division */
int mp_div_d(mp_int *a, mp_digit b, mp_int *c, mp_digit *d)
{
   mp_int t, t2;
   int res;
   
   REGFUNC("mp_div_d");
   VERIFY(a);
   if (c != NULL) { VERIFY(c); }
   
   if ((res = mp_init(&t)) != MP_OKAY) {
      DECFUNC();
      return res;
   }

   if ((res = mp_init(&t2)) != MP_OKAY) {
      mp_clear(&t);
      DECFUNC();
      return res;
   }

   mp_set(&t, b);
   res = mp_div(a, &t, c, &t2);

   if (d != NULL) {
      *d = t2.dp[0];
   }
   
   mp_clear(&t);
   mp_clear(&t2);
   DECFUNC();
   return res;
}

int mp_mod_d(mp_int *a, mp_digit b, mp_digit *c)
{
   mp_int t, t2;
   int res;
   
   REGFUNC("mp_mod_d");
   VERIFY(a);
      
   if ((res = mp_init(&t)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   
   if ((res = mp_init(&t2)) != MP_OKAY) {
      mp_clear(&t);
      DECFUNC();
      return res;
   }
   
   mp_set(&t, b);
   mp_div(a, &t, NULL, &t2);
   
   if (t2.sign == MP_NEG) {
      if ((res = mp_add_d(&t2, b, &t2)) != MP_OKAY) {
         mp_clear(&t);
         mp_clear(&t2);
         DECFUNC();
         return res;
      }
   }
   *c = t2.dp[0];
   mp_clear(&t);
   mp_clear(&t2);
   DECFUNC();
   return MP_OKAY;
}

int mp_expt_d(mp_int *a, mp_digit b, mp_int *c)
{
   int res, x;
   mp_int g;
   
   REGFUNC("mp_expt_d");
   VERIFY(a);
   VERIFY(c);
   
   if ((res = mp_init_copy(&g, a)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   
   /* set initial result */
   mp_set(c, 1);
   
   for (x = 0; x < (int)DIGIT_BIT; x++) {
       if ((res = mp_sqr(c, c)) != MP_OKAY) {
          mp_clear(&g);
          DECFUNC();
          return res;
       }
       
       if ((b & (mp_digit)(1<<(DIGIT_BIT-1))) != 0) {
          if ((res = mp_mul(c, &g, c)) != MP_OKAY) {
             mp_clear(&g);
             DECFUNC();
             return res;
          }
       }
       
       b <<= 1;
   }
   
   mp_clear(&g);
   DECFUNC();
   return MP_OKAY;
}

/* simple modular functions */

/* d = a + b (mod c) */
int mp_addmod(mp_int *a, mp_int *b, mp_int *c, mp_int *d)
{
   int res;
   mp_int t;
   
   REGFUNC("mp_addmod");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   VERIFY(d);
   
   if ((res = mp_init(&t)) != MP_OKAY) { 
      DECFUNC();
      return res;
   }
   
   if ((res = mp_add(a, b, &t)) != MP_OKAY) {
      mp_clear(&t);
      DECFUNC();
      return res;
   }
   res = mp_mod(&t, c, d);
   mp_clear(&t);
   DECFUNC();
   return res;
}

/* d = a - b (mod c) */
int mp_submod(mp_int *a, mp_int *b, mp_int *c, mp_int *d)
{
   int res;
   mp_int t;
   
   REGFUNC("mp_submod");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   VERIFY(d);
      
   if ((res = mp_init(&t)) != MP_OKAY) { 
      DECFUNC();
      return res;
   }
   
   if ((res = mp_sub(a, b, &t)) != MP_OKAY) {
      mp_clear(&t);
      DECFUNC();
      return res;
   }
   res = mp_mod(&t, c, d);
   mp_clear(&t);
   DECFUNC();
   return res;
}

/* d = a * b (mod c) */
int mp_mulmod(mp_int *a, mp_int *b, mp_int *c, mp_int *d)
{
   int res;
   mp_int t;
   
   REGFUNC("mp_mulmod");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   VERIFY(d);
   
   if ((res = mp_init(&t)) != MP_OKAY) { 
      DECFUNC();
      return res;
   }
   
   if ((res = mp_mul(a, b, &t)) != MP_OKAY) {
      mp_clear(&t);
      DECFUNC();
      return res;
   }
   res = mp_mod(&t, c, d);
   mp_clear(&t);
   DECFUNC();
   return res;
}

/* c = a * a (mod b) */
int mp_sqrmod(mp_int *a, mp_int *b, mp_int *c)
{
   int res;
   mp_int t;
   
   REGFUNC("mp_sqrmod");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);

   if ((res = mp_init(&t)) != MP_OKAY) { 
      DECFUNC();
      return res;
   }
   
   if ((res = mp_sqr(a, &t)) != MP_OKAY) {
      mp_clear(&t);
      DECFUNC();
      return res;
   }
   res = mp_mod(&t, b, c);
   mp_clear(&t);
   DECFUNC();
   return res;
}

/* Greatest Common Divisor using the binary method [Algorithm B, page 338, vol2 of TAOCP] 
 */
int mp_gcd(mp_int *a, mp_int *b, mp_int *c)
{
   mp_int u, v, t;
   int k, res, neg;
   
   REGFUNC("mp_gcd");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   /* either zero than gcd is the largest */
   if (mp_iszero(a) == 1 && mp_iszero(b) == 0) {
      DECFUNC();
      return mp_copy(b, c);
   }
   if (mp_iszero(a) == 0 && mp_iszero(b) == 1) {
      DECFUNC();
      return mp_copy(a, c);
   }
   if (mp_iszero(a) == 1 && mp_iszero(b) == 1) {
      mp_set(c, 1);
      DECFUNC();
      return MP_OKAY;
   }
   
   /* if both are negative they share (-1) as a common divisor */
   neg = (a->sign == b->sign) ? a->sign : MP_ZPOS;
   
   if ((res = mp_init_copy(&u, a)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   
   if ((res = mp_init_copy(&v, b)) != MP_OKAY) {
      goto __U;
   }
   
   /* must be positive for the remainder of the algorithm */
   u.sign = v.sign = MP_ZPOS;
   
   if ((res = mp_init(&t)) != MP_OKAY) {
      goto __V;
   }
   
   /* B1.  Find power of two */
   k = 0;
   while ((u.dp[0] & 1) == 0 && (v.dp[0] & 1) == 0) {
       ++k;
       if ((res = mp_div_2d(&u, 1, &u, NULL)) != MP_OKAY) {
          goto __T;
       }
       if ((res = mp_div_2d(&v, 1, &v, NULL)) != MP_OKAY) {
          goto __T;
       }
   }
   
   /* B2.  Initialize */
   if ((u.dp[0] & 1) == 1) {
      if ((res = mp_copy(&v, &t)) != MP_OKAY) {
         goto __T;
      }
      t.sign = MP_NEG;
   } else {
      if ((res = mp_copy(&u, &t)) != MP_OKAY) {
         goto __T;
      }
   }
   
   do {
      /* B3 (and B4).  Halve t, if even */
      while (t.used != 0 && (t.dp[0] & 1) == 0) {
          if ((res = mp_div_2d(&t, 1, &t, NULL)) != MP_OKAY) {
             goto __T;
          }
      }
      
      /* B5.  if t>0 then u=t otherwise v=-t */
      if (t.used != 0 && t.sign != MP_NEG) {
         if ((res = mp_copy(&t, &u)) != MP_OKAY) {
            goto __T;
         }
      } else {
         if ((res = mp_copy(&t, &v)) != MP_OKAY) {
            goto __T;
         }
         v.sign = (v.sign == MP_ZPOS) ? MP_NEG : MP_ZPOS;
      }
      
      /* B6.  t = u - v, if t != 0 loop otherwise terminate */
      if ((res = mp_sub(&u, &v, &t)) != MP_OKAY) {
         goto __T;
      }
   } while (t.used != 0);
   
   if ((res = mp_mul_2d(&u, k, &u)) != MP_OKAY) {
      goto __T;
   }
   
   mp_exch(&u, c);
   c->sign = neg;
   res = MP_OKAY;
__T:   mp_clear(&t);
__V:   mp_clear(&u);
__U:   mp_clear(&v);
   DECFUNC();
   return res;
}
         
/* computes least common multipble as a*b/(a, b) */
int mp_lcm(mp_int *a, mp_int *b, mp_int *c)
{
   int res;
   mp_int t;
   
   REGFUNC("mp_lcm");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   if ((res = mp_init(&t)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   
   if ((res = mp_mul(a, b, &t)) != MP_OKAY) {
      mp_clear(&t);
      DECFUNC();
      return res;
   }
   
   if ((res = mp_gcd(a, b, c)) != MP_OKAY) {
      mp_clear(&t);
      DECFUNC();
      return res;
   }
   
   res = mp_div(&t, c, c, NULL);
   mp_clear(&t);
   DECFUNC();
   return res;
}   

/* computes the modular inverse via binary extended euclidean algorithm, that is c = 1/a mod b */
static int fast_mp_invmod(mp_int *a, mp_int *b, mp_int *c)
{
   mp_int x, y, u, v, B, D;
   int res, neg;
   
   REGFUNC("fast_mp_invmod");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   if ((res = mp_init(&x)) != MP_OKAY) {
      goto __ERR;
   }
   
   if ((res = mp_init(&y)) != MP_OKAY) {
      goto __X;
   }
   
   if ((res = mp_init(&u)) != MP_OKAY) {
      goto __Y;
   }
   
   if ((res = mp_init(&v)) != MP_OKAY) {
      goto __U;
   }
   
   if ((res = mp_init(&B)) != MP_OKAY) {
      goto __V;
   }
 
   if ((res = mp_init(&D)) != MP_OKAY) {
      goto __B;
   }
   
   /* x == modulus, y == value to invert */
   if ((res = mp_copy(b, &x)) != MP_OKAY) {
      goto __D;
   }
   if ((res = mp_copy(a, &y)) != MP_OKAY) {
      goto __D;
   }
   
   if ((res = mp_abs(&y, &y)) != MP_OKAY) {
      goto __D;
   }
   
   /* 2. [modified] if x,y are both even then return an error! */
   if (mp_iseven(&x) == 1 && mp_iseven(&y) == 1) {
      res = MP_VAL;
      goto __D;
   }
   
   /* 3. u=x, v=y, A=1, B=0, C=0,D=1 */
   if ((res = mp_copy(&x, &u)) != MP_OKAY) {
      goto __D;
   }
   if ((res = mp_copy(&y, &v)) != MP_OKAY) {
      goto __D;
   }
   mp_set(&D, 1);
   

top:   
   /* 4.  while u is even do */
   while (mp_iseven(&u) == 1) {
      /* 4.1 u = u/2 */
      if ((res = mp_div_2(&u, &u)) != MP_OKAY) {
         goto __D;
      }
      /* 4.2 if A or B is odd then */
      if (mp_iseven(&B) == 0) {
         if ((res = mp_sub(&B, &x, &B)) != MP_OKAY) {
            goto __D;
         }
      }
      /* A = A/2, B = B/2 */
	  if ((res = mp_div_2(&B, &B)) != MP_OKAY) {
	     goto __D;
	  }
   }
   
  
   /* 5.  while v is even do */
   while (mp_iseven(&v) == 1) {
      /* 5.1 v = v/2 */
      if ((res = mp_div_2(&v, &v)) != MP_OKAY) {
         goto __D;
      }
      /* 5.2 if C,D are even then */
      if (mp_iseven(&D) == 0) {
         /* C = (C+y)/2, D = (D-x)/2 */
         if ((res = mp_sub(&D, &x, &D)) != MP_OKAY) {
            goto __D;
         }
      }
      /* C = C/2, D = D/2 */
	  if ((res = mp_div_2(&D, &D)) != MP_OKAY) {
	     goto __D;
	  }
   }
   
   /* 6.  if u >= v then */
   if (mp_cmp(&u, &v) != MP_LT) {
      /* u = u - v, A = A - C, B = B - D */
      if ((res = mp_sub(&u, &v, &u)) != MP_OKAY) {
         goto __D;
      }
   
      if ((res = mp_sub(&B, &D, &B)) != MP_OKAY) {
         goto __D;
      }
   } else {
      /* v - v - u, C = C - A, D = D - B */
      if ((res = mp_sub(&v, &u, &v)) != MP_OKAY) {
         goto __D;
      }
   
      if ((res = mp_sub(&D, &B, &D)) != MP_OKAY) {
         goto __D;
      }
   }
   
   /* if not zero goto step 4 */
   if (mp_iszero(&u) == 0) goto top;
   
   /* now a = C, b = D, gcd == g*v */
 
   /* if v != 1 then there is no inverse */
   if (mp_cmp_d(&v, 1) != MP_EQ) {
      res = MP_VAL;
      goto __D;
   }
   
   /* b is now the inverse */
   neg = a->sign;
   while (D.sign == MP_NEG) {
      if ((res = mp_add(&D, b, &D)) != MP_OKAY) {
         goto __D;
      }
   }
   mp_exch(&D, c);
   c->sign = neg;
   res = MP_OKAY;
   
__D:   mp_clear(&D);
__B:   mp_clear(&B);
__V:   mp_clear(&v);
__U:   mp_clear(&u);
__Y:   mp_clear(&y);
__X:   mp_clear(&x);
__ERR:
   DECFUNC();
   return res;
}

int mp_invmod(mp_int *a, mp_int *b, mp_int *c)
{
   mp_int x, y, u, v, A, B, C, D;
   int res;
   
   REGFUNC("mp_invmod");
   VERIFY(a);
   VERIFY(b);
   VERIFY(c);
   
   /* b cannot be negative */
   if (b->sign == MP_NEG) {
      return MP_VAL;
   }
   
   /* if the modulus is odd we can use a faster routine instead */
   if (mp_iseven(b) == 0) {
      res = fast_mp_invmod(a,b,c);
      DECFUNC();
      return res;
   }

   if ((res = mp_init(&x)) != MP_OKAY) {
      goto __ERR;
   }
   
   if ((res = mp_init(&y)) != MP_OKAY) {
      goto __X;
   }
   
   if ((res = mp_init(&u)) != MP_OKAY) {
      goto __Y;
   }
   
   if ((res = mp_init(&v)) != MP_OKAY) {
      goto __U;
   }
   
   if ((res = mp_init(&A)) != MP_OKAY) {
      goto __V;
   }
   
   if ((res = mp_init(&B)) != MP_OKAY) {
      goto __A;
   }
   
   if ((res = mp_init(&C)) != MP_OKAY) {
      goto __B;
   }
   
   if ((res = mp_init(&D)) != MP_OKAY) {
      goto __C;
   }
   
   /* x = a, y = b */
   if ((res = mp_copy(a, &x)) != MP_OKAY) {
      goto __D;
   }
   if ((res = mp_copy(b, &y)) != MP_OKAY) {
      goto __D;
   }
   
   if ((res = mp_abs(&x, &x)) != MP_OKAY) {
      goto __D;
   }
   
   /* 2. [modified] if x,y are both even then return an error! */
   if (mp_iseven(&x) == 1 && mp_iseven(&y) == 1) {
      res = MP_VAL;
      goto __D;
   }
   
   /* 3. u=x, v=y, A=1, B=0, C=0,D=1 */
   if ((res = mp_copy(&x, &u)) != MP_OKAY) {
      goto __D;
   }
   if ((res = mp_copy(&y, &v)) != MP_OKAY) {
      goto __D;
   }
   mp_set(&A, 1);
   mp_set(&D, 1);
   

top:   
   /* 4.  while u is even do */
   while (mp_iseven(&u) == 1) {
      /* 4.1 u = u/2 */
      if ((res = mp_div_2(&u, &u)) != MP_OKAY) {
         goto __D;
      }
      /* 4.2 if A or B is odd then */
      if (mp_iseven(&A) == 0 || mp_iseven(&B) == 0) {
         /* A = (A+y)/2, B = (B-x)/2 */
         if ((res = mp_add(&A, &y, &A)) != MP_OKAY) {
            goto __D;
         }
         if ((res = mp_sub(&B, &x, &B)) != MP_OKAY) {
            goto __D;
         }
      }
      /* A = A/2, B = B/2 */
	  if ((res = mp_div_2(&A, &A)) != MP_OKAY) {
	     goto __D;
	  }
	  if ((res = mp_div_2(&B, &B)) != MP_OKAY) {
	     goto __D;
	  }
   }
   
  
   /* 5.  while v is even do */
   while (mp_iseven(&v) == 1) {
      /* 5.1 v = v/2 */
      if ((res = mp_div_2(&v, &v)) != MP_OKAY) {
         goto __D;
      }
      /* 5.2 if C,D are even then */
      if (mp_iseven(&C) == 0 || mp_iseven(&D) == 0) {
         /* C = (C+y)/2, D = (D-x)/2 */
         if ((res = mp_add(&C, &y, &C)) != MP_OKAY) {
            goto __D;
         }
         if ((res = mp_sub(&D, &x, &D)) != MP_OKAY) {
            goto __D;
         }
      }
      /* C = C/2, D = D/2 */
	  if ((res = mp_div_2(&C, &C)) != MP_OKAY) {
	     goto __D;
	  }
	  if ((res = mp_div_2(&D, &D)) != MP_OKAY) {
	     goto __D;
	  }
   }
   
   /* 6.  if u >= v then */
   if (mp_cmp(&u, &v) != MP_LT) {
      /* u = u - v, A = A - C, B = B - D */
      if ((res = mp_sub(&u, &v, &u)) != MP_OKAY) {
         goto __D;
      }
   
      if ((res = mp_sub(&A, &C, &A)) != MP_OKAY) {
         goto __D;
      }
   
      if ((res = mp_sub(&B, &D, &B)) != MP_OKAY) {
         goto __D;
      }
   } else {
      /* v - v - u, C = C - A, D = D - B */
      if ((res = mp_sub(&v, &u, &v)) != MP_OKAY) {
         goto __D;
      }
   
      if ((res = mp_sub(&C, &A, &C)) != MP_OKAY) {
         goto __D;
      }
   
      if ((res = mp_sub(&D, &B, &D)) != MP_OKAY) {
         goto __D;
      }
   }
   
   /* if not zero goto step 4 */
   if (mp_iszero(&u) == 0) goto top;
   
   /* now a = C, b = D, gcd == g*v */
 
   /* if v != 1 then there is no inverse */
   if (mp_cmp_d(&v, 1) != MP_EQ) {
      res = MP_VAL;
      goto __D;
   }
   
   /* a is now the inverse */
   mp_exch(&C, c);
   res = MP_OKAY;
   
__D:   mp_clear(&D);
__C:   mp_clear(&C);
__B:   mp_clear(&B);
__A:   mp_clear(&A);
__V:   mp_clear(&v);
__U:   mp_clear(&u);
__Y:   mp_clear(&y);
__X:   mp_clear(&x);
__ERR:
   DECFUNC();
   return res;
}

/* pre-calculate the value required for Barrett reduction 
 * For a given modulus "b" it calulates the value required in "a"
 */
int mp_reduce_setup(mp_int *a, mp_int *b)
{
   int res;
   
   REGFUNC("mp_reduce_setup");
   VERIFY(a);
   VERIFY(b);
   
   if ((res = mp_2expt(a, b->used * 2 * DIGIT_BIT)) != MP_OKAY) {
      DECFUNC();
      return res;
   }
   res = mp_div(a, b, a, NULL);
   DECFUNC();
   return res;   
}

/* reduces x mod m, assumes 0 < x < m^2, mu is precomputed via mp_reduce_setup 
 * From HAC pp.604 Algorithm 14.42 
 */
int mp_reduce(mp_int *x, mp_int *m, mp_int *mu)
{
  mp_int   q;
  int      res, um = m->used;
  
  REGFUNC("mp_reduce");
  VERIFY(x);
  VERIFY(m);
  VERIFY(mu);
  
  if((res = mp_init_copy(&q, x)) != MP_OKAY) {
    DECFUNC();
    return res;
  }

  mp_rshd(&q, um - 1);       /* q1 = x / b^(k-1)  */
  
  /* according to HAC this is optimization is ok */
  if (((unsigned long)m->used) > (1UL<<(unsigned long)(DIGIT_BIT-1UL))) {
     if ((res = mp_mul(&q, mu, &q)) != MP_OKAY) {
        goto CLEANUP;
     }
  } else {
     if ((res = s_mp_mul_high_digs(&q, mu, &q, um-1)) != MP_OKAY) {
        goto CLEANUP;
     }
  }

  mp_rshd(&q, um + 1);       /* q3 = q2 / b^(k+1) */

  /* x = x mod b^(k+1), quick (no division) */
  if ((res = mp_mod_2d(x, DIGIT_BIT * (um + 1), x)) != MP_OKAY) {
     goto CLEANUP;
  }

  /* q = q * m mod b^(k+1), quick (no division) */
  if ((res = s_mp_mul_digs(&q, m, &q, um + 1)) != MP_OKAY) {
     goto CLEANUP;
  }

  /* x = x - q */
  if((res = mp_sub(x, &q, x)) != MP_OKAY)
    goto CLEANUP;

  /* If x < 0, add b^(k+1) to it */
  if(mp_cmp_d(x, 0) == MP_LT) {
    mp_set(&q, 1);
    if((res = mp_lshd(&q, um + 1)) != MP_OKAY)
      goto CLEANUP;
    if((res = mp_add(x, &q, x)) != MP_OKAY)
      goto CLEANUP;
  }

  /* Back off if it's too big */
  while(mp_cmp(x, m) != MP_LT) {
    if((res = s_mp_sub(x, m, x)) != MP_OKAY)
      break;
  }

 CLEANUP:
  mp_clear(&q);
  DECFUNC();

  return res;
}

/* setups the montgomery reduction stuff */
int mp_montgomery_setup(mp_int *a, mp_digit *mp)
{
   mp_int t, tt;
   int res;
   
   if ((res = mp_init(&t)) != MP_OKAY) {
      return res;
   }
   
   if ((res = mp_init(&tt)) != MP_OKAY) {
      goto __T;
   }
   
   /* tt = b */
   tt.dp[0] = 0;
   tt.dp[1] = 1;
   tt.used  = 2;

   /* t = m mod b */
   t.dp[0] = a->dp[0];
   t.used  = 1;

   /* t = 1/m mod b */
   if ((res = mp_invmod(&t, &tt, &t)) != MP_OKAY) {
      goto __TT;
   }
   
   /* t = -1/m mod b */
   *mp = ((mp_digit)1 << ((mp_digit)DIGIT_BIT)) - t.dp[0];
   
   res = MP_OKAY;
__TT: mp_clear(&tt);   
__T:  mp_clear(&t);
   return res;
}   

/* computes xR^-1 == x (mod N) via Montgomery Reduction (comba) */
static int fast_mp_montgomery_reduce(mp_int *a, mp_int *m, mp_digit mp)
{
   int ix, res, olduse;
   mp_digit ui;
   mp_word  W[512];
   
   REGFUNC("fast_mp_montgomery_reduce");
   VERIFY(a);
   VERIFY(m);
   
   /* get old used count */
   olduse = a->used;
   
   /* grow a as required */
   if (a->alloc < m->used+1) {
      if ((res = mp_grow(a, m->used+1)) != MP_OKAY) {
         DECFUNC();
         return res;
      }
   }
   
   /* copy the digits of a */
   for (ix = 0; ix < a->used; ix++) {
       W[ix] = a->dp[ix];
   }
   
   /* zero the high words */
   for (; ix < m->used * 2 + 1; ix++) {
       W[ix] = 0;
   }
     
   for (ix = 0; ix < m->used; ix++) {
       /* ui = ai * m' mod b 
        *
        * We avoid a double precision multiplication (which isn't required)
        * by casting the value down to a mp_digit.  Note this requires that W[ix-1] have
        * the carry cleared (see after the inner loop)
        */
       ui = (((mp_digit)(W[ix] & MP_MASK)) * mp) & MP_MASK;
       
       /* a = a + ui * m * b^i 
        *
        * This is computed in place and on the fly.  The multiplication 
        * by b^i is handled by offseting which columns the results 
        * are added to.
        *
        * Note the comba method normally doesn't handle carries in the inner loop
        * In this case we fix the carry from the previous column since the Montgomery
        * reduction requires digits of the result (so far) [see above] to work.  This is 
        * handled by fixing up one carry after the inner loop.  The carry fixups are done
        * in order so after these loops the first m->used words of W[] have the carries
        * fixed
        */       
       { 
          register int      iy;
          register mp_digit *tmpx;
          register mp_word  *_W;
          
          /* aliases */
          tmpx = m->dp;
          _W   = W + ix;
          
          /* inner loop */
          for (iy = 0; iy < m->used; iy++) {
              *_W++        += ((mp_word)ui) * ((mp_word)*tmpx++);
          }
       }

       /* now fix carry for next digit, W[ix+1] */
       W[ix+1] += W[ix] >> ((mp_word)DIGIT_BIT);
   }
   
   /* nox fix rest of carries */
   for (++ix; ix <= m->used * 2 + 1; ix++) {
       W[ix]   += (W[ix-1] >> ((mp_word)DIGIT_BIT));
   }
   
   /* copy out, A = A/b^n 
    *
    * The result is A/b^n but instead of converting from an array of mp_word
    * to mp_digit than calling mp_rshd we just copy them in the right
    * order 
    */
   for (ix = 0; ix < m->used + 1; ix++) { 
       a->dp[ix] = W[ix+m->used] & ((mp_word)MP_MASK);
   }
   
   /* set the max used */
   a->used = m->used + 1;

   /* zero oldused digits, if the input a was larger than 
    * m->used+1 we'll have to clear the digits */  
   for (; ix < olduse; ix++) {
       a->dp[ix] = 0;
   }

   mp_clamp(a);
   
   /* if A >= m then A = A - m */
   if (mp_cmp_mag(a, m) != MP_LT) {
      if ((res = s_mp_sub(a, m, a)) != MP_OKAY) {
         DECFUNC();
         return res;
      }
   }   
   
   DECFUNC();
   return MP_OKAY;
}

/* computes xR^-1 == x (mod N) via Montgomery Reduction */
int mp_montgomery_reduce(mp_int *a, mp_int *m, mp_digit mp)
{
   int ix, res, digs;
   mp_digit ui;
   
   REGFUNC("mp_montgomery_reduce");
   VERIFY(a);
   VERIFY(m);
   
   digs = m->used * 2 + 1;
   if ((digs < 512) && digs < (1<<( (CHAR_BIT*sizeof(mp_word)) - (2*DIGIT_BIT)))) {
      res = fast_mp_montgomery_reduce(a, m, mp);
      DECFUNC();
      return res;
   }  

   if (a->alloc < m->used*2+1) {
      if ((res = mp_grow(a, m->used*2+1)) != MP_OKAY) {
         DECFUNC();
         return res;
      }
   }
   a->used = m->used * 2 + 1;
      
   for (ix = 0; ix < m->used; ix++) {
       /* ui = ai * m' mod b */
       ui = (a->dp[ix] * mp) & MP_MASK;
       
       /* a = a + ui * m * b^i */
       { 
          register int      iy;
          register mp_digit *tmpx, *tmpy, mu;
          register mp_word  r;
          
          /* aliases */
          tmpx = m->dp;
          tmpy = a->dp + ix;
          
          mu  = 0;
          for (iy = 0; iy < m->used; iy++) {
              r             = ((mp_word)ui) * ((mp_word)*tmpx++) + ((mp_word)mu) + ((mp_word)*tmpy);
              mu            = (r >> ((mp_word)DIGIT_BIT));
              *tmpy++       = (r & ((mp_word)MP_MASK));
          }
          /* propagate carries */
          while (mu) {
             *tmpy            += mu;
             mu                = (*tmpy>>DIGIT_BIT)&1;
             *tmpy++          &= MP_MASK;
          }
       }
   }
   
   /* A = A/b^n */
   mp_rshd(a, m->used);
   
   /* if A >= m then A = A - m */
   if (mp_cmp_mag(a, m) != MP_LT) {
      if ((res = s_mp_sub(a, m, a)) != MP_OKAY) {
         DECFUNC();
         return res;
      }
   }
   
   DECFUNC();
   return MP_OKAY;
}

/* computes Y == G^X mod P, HAC pp.616, Algorithm 14.85 
 *
 * Uses a left-to-right k-ary sliding window to compute the modular exponentiation.
 * The value of k changes based on the size of the exponent.
 *
 * Uses Montgomery reduction 
 */
static int mp_exptmod_fast(mp_int *G, mp_int *X, mp_int *P, mp_int *Y)
{
   mp_int M[256], res;
   mp_digit buf, mp;
   int err, bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;
   
   REGFUNC("mp_exptmod_fast");
   VERIFY(G);
   VERIFY(X);
   VERIFY(P);
   VERIFY(Y);
   
   /* find window size */
   x = mp_count_bits(X);
        if (x <= 7)     { winsize = 2; }
   else if (x <= 36)    { winsize = 3; }
   else if (x <= 140)   { winsize = 4; }
   else if (x <= 450)   { winsize = 5; }
   else if (x <= 1303)  { winsize = 6; }
   else if (x <= 3529)  { winsize = 7; }
   else                 { winsize = 8; }

   /* init G array */
   for (x = 0; x < (1<<winsize); x++) {
      if ((err = mp_init_size(&M[x], 1)) != MP_OKAY) {
         for (y = 0; y < x; y++) {
            mp_clear(&M[y]);
         }
         DECFUNC();
         return err;
      }
   }
   
   /* now setup montgomery  */
   if ((err = mp_montgomery_setup(P, &mp)) != MP_OKAY) {
      goto __M;
   }
   
   /* setup result */
   if ((err = mp_init(&res)) != MP_OKAY) {
      goto __RES;
   }

   /* now we need R mod m */
   if ((err = mp_2expt(&res, P->used * DIGIT_BIT)) != MP_OKAY) {
      goto __RES;
   }
      
   /* res = R mod m */
   if ((err = mp_mod(&res, P, &res)) != MP_OKAY) {
      goto __RES;
   }   
   
   /* create M table 
    *
    * The M table contains powers of the input base, e.g. M[x] = G^x mod P
    *
    * The first half of the table is not computed though accept for M[0] and M[1]
    */
   if ((err = mp_mod(G, P, &M[1])) != MP_OKAY) {
      goto __RES;
   }
   
   /* now set M[1] to G * R mod m */
   if ((err = mp_mulmod(&M[1], &res, P, &M[1])) != MP_OKAY) {
      goto __RES;
   }
      
   /* compute the value at M[1<<(winsize-1)] by squaring M[1] (winsize-1) times */
   if ((err = mp_copy(&M[1], &M[1<<(winsize-1)])) != MP_OKAY) {
      goto __RES;
   }
   
   for (x = 0; x < (winsize-1); x++) {
       if ((err = mp_sqr(&M[1<<(winsize-1)], &M[1<<(winsize-1)])) != MP_OKAY) {
          goto __RES;
       }
       if ((err = mp_montgomery_reduce(&M[1<<(winsize-1)], P, mp)) != MP_OKAY) {
          goto __RES;
       }
   }  
   
   /* create upper table */
   for (x = (1<<(winsize-1))+1; x < (1 << winsize); x++) {
       if ((err = mp_mul(&M[x-1], &M[1], &M[x])) != MP_OKAY) {
          goto __RES;
       }
       if ((err = mp_montgomery_reduce(&M[x], P, mp)) != MP_OKAY) {
          goto __RES;
       }
   }

   /* set initial mode and bit cnt */
   mode   = 0;
   bitcnt = 0;
   buf    = 0;
   digidx = X->used - 1;
   bitcpy = bitbuf = 0;
  
   bitcnt = 1;
   for (;;) {
      /* grab next digit as required */
      if (--bitcnt == 0) {
         if (digidx == -1) {
            break;
         }
         buf = X->dp[digidx--];
         bitcnt = (int)DIGIT_BIT;
      }
      
      /* grab the next msb from the exponent */
      y = (buf >> (DIGIT_BIT - 1)) & 1;
      buf <<= 1;
    
      /* if the bit is zero and mode == 0 then we ignore it 
       * These represent the leading zero bits before the first 1 bit
       * in the exponent.  Technically this opt is not required but it 
       * does lower the # of trivial squaring/reductions used
       */
      if (mode == 0 && y == 0) continue;
      
      /* if the bit is zero and mode == 1 then we square */
      if (y == 0 && mode == 1) {
         if ((err = mp_sqr(&res, &res)) != MP_OKAY) {
            goto __RES;
         }
         if ((err = mp_montgomery_reduce(&res, P, mp)) != MP_OKAY) {
            goto __RES;
         }
         continue;
      }
      
      /* else we add it to the window */
      bitbuf  |= (y<<(winsize-++bitcpy));
      mode     = 2;
      
      if (bitcpy == winsize) {
         /* ok window is filled so square as required and multiply multiply */
         /* square first */
         for (x = 0; x < winsize; x++) {
            if ((err = mp_sqr(&res, &res)) != MP_OKAY) {
               goto __RES;
            }
            if ((err = mp_montgomery_reduce(&res, P, mp)) != MP_OKAY) {
               goto __RES;
            }
         }
         
         /* then multiply */
         if ((err = mp_mul(&res, &M[bitbuf], &res)) != MP_OKAY) {
            goto __RES;
         }
         if ((err = mp_montgomery_reduce(&res, P, mp)) != MP_OKAY) {
            goto __RES;
         }
         
         /* empty window and reset */
         bitcpy = bitbuf = 0;
         mode   = 1;
      }
   }
   
   /* if bits remain then square/multiply */
   if (mode == 2 && bitcpy > 0) {
      /* square then multiply if the bit is set */
      for (x = 0; x < bitcpy; x++) {
         if ((err = mp_sqr(&res, &res)) != MP_OKAY) {
            goto __RES;
         }
         if ((err = mp_montgomery_reduce(&res, P, mp)) != MP_OKAY) {
            goto __RES;
         }
         
         bitbuf <<= 1;
         if ((bitbuf & (1<<winsize)) != 0) {
            /* then multiply */
            if ((err = mp_mul(&res, &M[1], &res)) != MP_OKAY) {
               goto __RES;
            }
            if ((err = mp_montgomery_reduce(&res, P, mp)) != MP_OKAY) {
               goto __RES;
            }
         }
      }
   }
   
   /* fixup result */
   if ((err = mp_montgomery_reduce(&res, P, mp)) != MP_OKAY) {
      goto __RES;
   } 
   
   mp_exch(&res, Y);
   err = MP_OKAY;
__RES: mp_clear(&res);
__M  :
   for (x = 0; x < (1<<winsize); x++) {
      mp_clear(&M[x]);
   }
   DECFUNC();
   return err;
}

int mp_exptmod(mp_int *G, mp_int *X, mp_int *P, mp_int *Y)
{
   mp_int M[256], res, mu;
   mp_digit buf;
   int err, bitbuf, bitcpy, bitcnt, mode, digidx, x, y, winsize;
   
   REGFUNC("mp_exptmod");
   VERIFY(G);
   VERIFY(X);
   VERIFY(P);
   VERIFY(Y);
   
   /* if the modulus is odd use the fast method */
   if (mp_isodd(P) == 1 && P->used > 4 && P->used < MONTGOMERY_EXPT_CUTOFF) {
      err = mp_exptmod_fast(G, X, P, Y);
      DECFUNC();
      return err;
   }   

   /* find window size */
   x = mp_count_bits(X);
        if (x <= 7)     { winsize = 2; }
   else if (x <= 36)    { winsize = 3; }
   else if (x <= 140)   { winsize = 4; }
   else if (x <= 450)   { winsize = 5; }
   else if (x <= 1303)  { winsize = 6; }
   else if (x <= 3529)  { winsize = 7; }
   else                 { winsize = 8; }
   
   /* init G array */
   for (x = 0; x < (1<<winsize); x++) {
      if ((err = mp_init_size(&M[x], 1)) != MP_OKAY) {
         for (y = 0; y < x; y++) {
            mp_clear(&M[y]);
         }
         DECFUNC();
         return err;
      }
   }

   /* create mu, used for Barrett reduction */
   if ((err = mp_init(&mu)) != MP_OKAY) {
      goto __M;
   }
   if ((err = mp_reduce_setup(&mu, P)) != MP_OKAY) {
      goto __MU;
   }
   
   /* create M table 
    *
    * The M table contains powers of the input base, e.g. M[x] = G^x mod P
    *
    * The first half of the table is not computed though accept for M[0] and M[1]
    */
   if ((err = mp_mod(G, P, &M[1])) != MP_OKAY) {
      goto __MU;
   }
   
   /* compute the value at M[1<<(winsize-1)] by squaring M[1] (winsize-1) times */
   if ((err = mp_copy(&M[1], &M[1<<(winsize-1)])) != MP_OKAY) {
      goto __MU;
   }
   
   for (x = 0; x < (winsize-1); x++) {
       if ((err = mp_sqr(&M[1<<(winsize-1)], &M[1<<(winsize-1)])) != MP_OKAY) {
          goto __MU;
       }
       if ((err = mp_reduce(&M[1<<(winsize-1)], P, &mu)) != MP_OKAY) {
          goto __MU;
       }
   }  
   
   /* create upper table */
   for (x = (1<<(winsize-1))+1; x < (1 << winsize); x++) {
       if ((err = mp_mul(&M[x-1], &M[1], &M[x])) != MP_OKAY) {
          goto __MU;
       }
       if ((err = mp_reduce(&M[x], P, &mu)) != MP_OKAY) {
          goto __MU;
       }
   }
   
   /* setup result */
   if ((err = mp_init(&res)) != MP_OKAY) {
      goto __MU;
   }
   mp_set(&res, 1);
   
   /* set initial mode and bit cnt */
   mode   = 0;
   bitcnt = 0;
   buf    = 0;
   digidx = X->used - 1;
   bitcpy = bitbuf = 0;
   
   bitcnt = 1;
   for (;;) {
      /* grab next digit as required */
      if (--bitcnt == 0) {
         if (digidx == -1) {
            break;
         }
         buf = X->dp[digidx--];
         bitcnt = (int)DIGIT_BIT;
      }
      
      /* grab the next msb from the exponent */
      y = (buf >> (DIGIT_BIT - 1)) & 1;
      buf <<= 1;
    
      /* if the bit is zero and mode == 0 then we ignore it 
       * These represent the leading zero bits before the first 1 bit
       * in the exponent.  Technically this opt is not required but it 
       * does lower the # of trivial squaring/reductions used
       */
      if (y == 0 && mode == 0) continue;
      
      /* if the bit is zero and mode == 1 then we square */
      if (y == 0 && mode == 1) {
         if ((err = mp_sqr(&res, &res)) != MP_OKAY) {
            goto __RES;
         }
         if ((err = mp_reduce(&res, P, &mu)) != MP_OKAY) {
            goto __RES;
         }
         continue;
      }
      
      /* else we add it to the window */
      bitbuf  |= (y<<(winsize-++bitcpy));
      mode     = 2;
      
      if (bitcpy == winsize) {
         /* ok window is filled so square as required and multiply multiply */
         /* square first */
         for (x = 0; x < winsize; x++) {
            if ((err = mp_sqr(&res, &res)) != MP_OKAY) {
               goto __RES;
            }
            if ((err = mp_reduce(&res, P, &mu)) != MP_OKAY) {
               goto __RES;
            }
         }
         
         /* then multiply */
         if ((err = mp_mul(&res, &M[bitbuf], &res)) != MP_OKAY) {
            goto __MU;
         }
         if ((err = mp_reduce(&res, P, &mu)) != MP_OKAY) {
            goto __MU;
         }
         
         /* empty window and reset */
         bitcpy = bitbuf = 0;
         mode   = 1;
      }
   }
   
   /* if bits remain then square/multiply */
   if (mode == 2 && bitcpy > 0) {
      /* square then multiply if the bit is set */
      for (x = 0; x < bitcpy; x++) {
         if ((err = mp_sqr(&res, &res)) != MP_OKAY) {
            goto __RES;
         }
         if ((err = mp_reduce(&res, P, &mu)) != MP_OKAY) {
            goto __RES;
         }
         
         bitbuf <<= 1;
         if ((bitbuf & (1<<winsize)) != 0) {
            /* then multiply */
            if ((err = mp_mul(&res, &M[1], &res)) != MP_OKAY) {
               goto __RES;
            }
            if ((err = mp_reduce(&res, P, &mu)) != MP_OKAY) {
               goto __RES;
            }
         }
      }
   }
   
   mp_exch(&res, Y);
   err = MP_OKAY;
__RES: mp_clear(&res);
__MU : mp_clear(&mu);
__M  :
   for (x = 0; x < (1<<winsize); x++) {
      mp_clear(&M[x]);
   }
   DECFUNC();
   return err;
}

/* computes a = 2^b */
int mp_2expt(mp_int *a, int b)
{
   int res;
   
   mp_zero(a);
   if ((res = mp_grow(a, b/DIGIT_BIT + 1)) != MP_OKAY) {
      return res;
   }
   a->used = b/DIGIT_BIT + 1;
   a->dp[b/DIGIT_BIT] = 1 << (b % DIGIT_BIT);
   
   return MP_OKAY;
}   
   

/* find the n'th root of an integer 
 *
 * Result found such that (c)^b <= a and (c+1)^b > a 
 */
int mp_n_root(mp_int *a, mp_digit b, mp_int *c)
{
   mp_int t1, t2, t3;
   int res, neg;
   
   /* input must be positive if b is even*/
   if ((b&1) == 0 && a->sign == MP_NEG) {
      return MP_VAL;
   }
   
   if ((res = mp_init(&t1)) != MP_OKAY) {
      return res;
   }
   
   if ((res = mp_init(&t2)) != MP_OKAY) {
      goto __T1;
   }
   
   if ((res = mp_init(&t3)) != MP_OKAY) {
      goto __T2;
   }

   /* if a is negative fudge the sign but keep track */
   neg     = a->sign;
   a->sign = MP_ZPOS;

   /* t2 = 2 */
   mp_set(&t2, 2);
  
   do {
      /* t1 = t2 */
      if ((res = mp_copy(&t2, &t1)) != MP_OKAY) {
         goto __T3;
      }

      /* t2 = t1 - ((t1^b - a) / (b * t1^(b-1))) */
      if ((res = mp_expt_d(&t1, b-1, &t3)) != MP_OKAY) {            /* t3 = t1^(b-1) */
         goto __T3;
      }

      /* numerator */
      if ((res = mp_mul(&t3, &t1, &t2)) != MP_OKAY) {               /* t2 = t1^b */
         goto __T3;
      }
      
      if ((res = mp_sub(&t2, a, &t2)) != MP_OKAY) {                 /* t2 = t1^b - a */
         goto __T3;
      }

      if ((res = mp_mul_d(&t3, b, &t3)) != MP_OKAY) {               /* t3 = t1^(b-1) * b  */
         goto __T3;
      }
      
      if ((res = mp_div(&t2, &t3, &t3, NULL)) != MP_OKAY) {         /* t3 = (t1^b - a)/(b * t1^(b-1)) */
         goto __T3;
      }
      
      if ((res = mp_sub(&t1, &t3, &t2)) != MP_OKAY) {
         goto __T3;
      }
   } while (mp_cmp(&t1, &t2) != MP_EQ);
   
   /* result can be off by a few so check */
   for (;;) {
      if ((res = mp_expt_d(&t1, b, &t2)) != MP_OKAY) {
         goto __T3;
      }
   
      if (mp_cmp(&t2, a) == MP_GT) {
         if ((res = mp_sub_d(&t1, 1, &t1)) != MP_OKAY) {
            goto __T3;
         }
      } else {
         break;
      }
   }      
   
   /* reset the sign of a first */
   a->sign = neg;
   
   /* set the result */
   mp_exch(&t1, c);
   
   /* set the sign of the result */
   c->sign = neg;   
   
   res = MP_OKAY;
   
__T3:  mp_clear(&t3);
__T2:  mp_clear(&t2);
__T1:  mp_clear(&t1);
   return res;
}

/* computes the jacobi c = (a | n) (or Legendre if b is prime) 
 * HAC pp. 73 Algorithm 2.149 
 */
int mp_jacobi(mp_int *a, mp_int *n, int *c)
{
   mp_int a1, n1, e;
   int s, r, res;
   mp_digit residue;
   
   /* step 1.  if a == 0, return 0 */
   if (mp_iszero(a) == 1) {
      *c = 0;
      return MP_OKAY;
   }
   
   /* step 2.  if a == 1, return 1 */
   if (mp_cmp_d(a, 1) == MP_EQ) {
      *c = 1;
      return MP_OKAY;
   }
   
   /* default */
   s = 0;
   
   /* step 3.  write a = a1 * 2^e  */
   if ((res = mp_init_copy(&a1, a)) != MP_OKAY) {
      return res;
   }
   
   if ((res = mp_init(&n1)) != MP_OKAY) {
      goto __A1;
   }
   
   if ((res = mp_init(&e)) != MP_OKAY) {
      goto __N1;
   }
   
   while (mp_iseven(&a1) == 1) {
       if ((res = mp_add_d(&e, 1, &e)) != MP_OKAY) {
          goto __E;
       }
       
       if ((res = mp_div_2(&a1, &a1)) != MP_OKAY) {
          goto __E;
       }
   }
   
   /* step 4.  if e is even set s=1 */
   if (mp_iseven(&e) == 1) {
      s = 1;
   } else {
      /* else set s=1 if n = 1/7 (mod 8) or s=-1 if n = 3/5 (mod 8) */
      if ((res = mp_mod_d(n, 8, &residue)) != MP_OKAY) {
         goto __E;
      }
      
      if (residue == 1 || residue == 7) {
         s = 1;
      } else if (residue == 3 || residue == 5) {
         s = -1;
      }
   }
   
   /* step 5.  if n == 3 (mod 4) *and* a1 == 3 (mod 4) then s = -s */
   if ((res = mp_mod_d(n, 4, &residue)) != MP_OKAY) {
      goto __E;
   }
   if (residue == 3) {
      if ((res = mp_mod_d(&a1, 4, &residue)) != MP_OKAY) {
         goto __E;
      }
      if (residue == 3) {
         s = -s;
      }
   }
   
   /* if a1 == 1 we're done */
   if (mp_cmp_d(&a1, 1) == MP_EQ) {
      *c = s;
   } else {
      /* n1 = n mod a1 */
      if ((res = mp_mod(n, &a1, &n1)) != MP_OKAY) {
         goto __E;
      }
      if ((res = mp_jacobi(&n1, &a1, &r)) != MP_OKAY) {
         goto __E;
      }
      *c = s * r;
   }
   
   /* done */
   res = MP_OKAY;
__E:   mp_clear(&e);
__N1:  mp_clear(&n1);
__A1:  mp_clear(&a1);
   return res;
}

/* --> radix conversion <-- */
/* reverse an array, used for radix code */
static void reverse(unsigned char *s, int len)
{
   int ix, iy;
   unsigned char t;
   
   ix = 0; 
   iy = len - 1;
   while (ix < iy) {
       t = s[ix]; s[ix] = s[iy]; s[iy] = t;
       ++ix;
       --iy;
   }
}

/* returns the number of bits in an int */
int mp_count_bits(mp_int *a)
{
   int r;
   mp_digit q;
   
   if (a->used == 0) {
      return 0;
   }
    
   r = (a->used - 1) * DIGIT_BIT;
   q = a->dp[a->used - 1];
   while (q) {
      ++r;
      q >>= ((mp_digit)1);
   }
   return r;
}

/* reads a unsigned char array, assumes the msb is stored first [big endian] */
int mp_read_unsigned_bin(mp_int *a, unsigned char *b, int c)
{
   int res;
   mp_zero(a);
   while (c-- > 0) {
       if ((res = mp_mul_2d(a, 8, a)) != MP_OKAY) {
          return res;
       }
       
       if (DIGIT_BIT != 7) {
           a->dp[0] |= *b++;
           a->used  += 1;
       } else {
           a->dp[0]  = (*b & MP_MASK);
           a->dp[1] |= ((*b++ >> 7U) & 1);
           a->used  += 2;
       }
   }
   mp_clamp(a);
   return MP_OKAY;
}   

/* read signed bin, big endian, first byte is 0==positive or 1==negative */
int mp_read_signed_bin(mp_int *a, unsigned char *b, int c)
{
   int res;
   
   if ((res = mp_read_unsigned_bin(a, b + 1, c - 1)) != MP_OKAY) {
      return res;
   }
   a->sign = ((b[0] == (unsigned char)0) ? MP_ZPOS : MP_NEG);
   return MP_OKAY;
}

/* store in unsigned [big endian] format */
int mp_to_unsigned_bin(mp_int *a, unsigned char *b)
{
   int x, res;
   mp_int t;
   
   if ((res = mp_init_copy(&t, a)) != MP_OKAY) {
      return res;
   }
   
   x = 0;
   while (mp_iszero(&t) == 0) {
      if (DIGIT_BIT != 7) {
         b[x++] = (unsigned char)(t.dp[0] & 255);
      } else {
         b[x++] = (unsigned char)(t.dp[0] | ((t.dp[1] & 0x01) << 7));
      }
      if ((res = mp_div_2d(&t, 8, &t, NULL))  != MP_OKAY) {
         mp_clear(&t);
         return res;
      }
   }
   reverse(b, x);
   mp_clear(&t);
   return MP_OKAY;
}

/* store in signed [big endian] format */
int mp_to_signed_bin(mp_int *a, unsigned char *b)
{
   int res;
   
   if ((res = mp_to_unsigned_bin(a, b+1)) != MP_OKAY) {
      return res;
   }
   b[0] = (unsigned char)((a->sign == MP_ZPOS) ? 0 : 1);
   return MP_OKAY;
}

/* get the size for an unsigned equivalent */
int mp_unsigned_bin_size(mp_int *a)
{
   int size = mp_count_bits(a);
   return (size/8 + ((size&7) != 0 ? 1 : 0));
}

/* get the size for an signed equivalent */
int mp_signed_bin_size(mp_int *a)
{
   return 1 + mp_unsigned_bin_size(a);
}

/* read a string [ASCII] in a given radix */
int mp_read_radix(mp_int *a, char *str, int radix)
{
   int y, res, neg;
   char ch;
   
   if (radix < 2 || radix > 64) {
      return MP_VAL;
   }

   if (*str == '-') {
      ++str;
      neg = MP_NEG;
   } else {
      neg = MP_ZPOS;
   }
   
   mp_zero(a);
   while (*str) {
      ch = (char)((radix < 36) ? toupper(*str) : *str);
      for (y = 0; y < 64; y++) {
          if (ch == s_rmap[y]) {
             break;
          }
      }
      
      if (y < radix) {
         if ((res = mp_mul_d(a, (mp_digit)radix, a)) != MP_OKAY) {
            return res;
         }
         if ((res = mp_add_d(a, (mp_digit)y, a)) != MP_OKAY) {
            return res;
         }
      } else {
         break;
      }
      ++str;
   }
   a->sign = neg;
   return MP_OKAY;
}

/* stores a bignum as a ASCII string in a given radix (2..64) */
int mp_toradix(mp_int *a, char *str, int radix)
{
   int res, digs;
   mp_int t;
   mp_digit d;
   char *_s = str;
   
   if (radix < 2 || radix > 64) {
      return MP_VAL;
   }

   if ((res = mp_init_copy(&t, a)) != MP_OKAY) {
      return res;
   }
   
   if (t.sign == MP_NEG) { 
      ++_s;
      *str++ = '-';
      t.sign = MP_ZPOS;
   }
   
   digs = 0;
   while (mp_iszero(&t) == 0) {
       if ((res = mp_div_d(&t, (mp_digit)radix, &t, &d)) != MP_OKAY) {
          mp_clear(&t);
          return res;
       }
       *str++ = s_rmap[d];
       ++digs;
   }
   reverse((unsigned char *)_s, digs);
   *str++ = '\0';
   mp_clear(&t);
   return MP_OKAY;
}

/* returns size of ASCII reprensentation */
int mp_radix_size(mp_int *a, int radix)
{
   int res, digs;
   mp_int t;
   mp_digit d;
   
   /* special case for binary */
   if (radix == 2) {
      return mp_count_bits(a) + (a->sign == MP_NEG ? 1 : 0) + 1;
   }
      
   if (radix < 2 || radix > 64) {
      return 0;
   }

   if ((res = mp_init_copy(&t, a)) != MP_OKAY) {
      return 0;
   }
   
   digs = 0;
   if (t.sign == MP_NEG) { 
      ++digs;
      t.sign = MP_ZPOS;
   }
   
   while (mp_iszero(&t) == 0) {
       if ((res = mp_div_d(&t, (mp_digit)radix, &t, &d)) != MP_OKAY) {
          mp_clear(&t);
          return 0;
       }
       ++digs;
   }
   mp_clear(&t);
   return digs + 1;
}

