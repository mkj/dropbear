/* polynomial basis GF(2^w) routines */
#include "mycrypt.h"

#ifdef GF

#define FORLOOP for (i = 0; i < LSIZE; i++) 

/* c = a + b */
void gf_add(gf_intp a, gf_intp b, gf_intp c)
{
   int i;
   FORLOOP c[i] = a[i]^b[i];
}

/* b = a */
void gf_copy(gf_intp a, gf_intp b)
{
   int i;
   FORLOOP b[i] = a[i];
}

/* a = 0 */
void gf_zero(gf_intp a)
{
   int i;
   FORLOOP a[i] = 0;
}

/* is a zero? */
int gf_iszero(gf_intp a)
{
   int i;
   FORLOOP if (a[i]) {
      return 0;
   }
   return 1;
}

/* is a one? */
int gf_isone(gf_intp a)
{ 
   int i;
   for (i = 1; i < LSIZE; i++) {
       if (a[i]) {
          return 0;
       }
   }
   return a[0] == 1;
}

/* b = a << 1*/
void gf_shl(gf_intp a, gf_intp b)
{
   int i;
   gf_int tmp;

   gf_copy(a, tmp);
   for (i = LSIZE-1; i > 0; i--) 
       b[i] = ((tmp[i]<<1)|((tmp[i-1]&0xFFFFFFFFUL)>>31))&0xFFFFFFFFUL;
   b[0] = (tmp[0] << 1)&0xFFFFFFFFUL;
   gf_zero(tmp);
}

/* b = a >> 1 */
void gf_shr(gf_intp a, gf_intp b)
{
   int i;
   gf_int tmp;

   gf_copy(a, tmp);
   for (i = 0; i < LSIZE-1; i++)
       b[i] = (((tmp[i]&0xFFFFFFFFUL)>>1)|(tmp[i+1]<<31))&0xFFFFFFFFUL;
   b[LSIZE-1] = (tmp[LSIZE-1]&0xFFFFFFFFUL)>>1;
   gf_zero(tmp);
}

/* returns -1 if its zero, otherwise degree of a */
int gf_deg(gf_intp a)
{
   int i, ii;
   unsigned long t;

   ii = -1;
   for (i = LSIZE-1; i >= 0; i--)
       if (a[i]) {
          for (t = a[i], ii = 0; t; t >>= 1, ++ii);
          break;
       }
   if (i == -1) i = 0;
   return (i<<5)+ii;
}

/* c = ab */
void gf_mul(gf_intp a, gf_intp b, gf_intp c)
{
   gf_int ta, tb;
   int i, n;

   gf_copy(a, ta);
   gf_copy(b, tb);
   gf_zero(c);
   n = gf_deg(ta)+1;
   for (i = 0; i < n; i++) {
       if (ta[i>>5]&(1<<(i&31)))
          gf_add(c, tb, c);
       gf_shl(tb, tb);
   }
   gf_zero(ta);
   gf_zero(tb);
}

/* q = a/b, r = a%b */
void gf_div(gf_intp a, gf_intp b, gf_intp q, gf_intp r)
{
   gf_int ta, tb, shifts[LSIZE*32];
   int i, magb, mag;

   mag  = gf_deg(a);
   magb = gf_deg(b);

   /* special cases */
   if (magb > mag) {
      gf_copy(a, r);
      gf_zero(q);
      return;
   }
   if (magb == -1) {
      return;
   }

   /* copy locally */
   gf_copy(a, ta);
   gf_copy(b, tb);
   gf_zero(q);

   /* make shifted versions of "b" */
   gf_copy(tb, shifts[0]);
   for (i = 1; i <= (mag-magb); i++) 
       gf_shl(shifts[i-1], shifts[i]);

   while (mag >= magb) {
       i = (mag - magb);
       q[i>>5] |= (1<<(i&31));
       gf_add(ta, shifts[i], ta);
       mag = gf_deg(ta);
   }
   gf_copy(ta, r);
   gf_zero(ta);
   gf_zero(tb);
   zeromem(shifts, sizeof(shifts));
}

/* b = a mod m */
void gf_mod(gf_intp a, gf_intp m, gf_intp b)
{
   gf_int tmp;
   gf_div(a,m,tmp,b);
   gf_zero(tmp);
}

/* c = ab (mod m) */
void gf_mulmod(gf_intp a, gf_intp b, gf_intp m, gf_intp c)
{
   gf_int tmp;
   gf_mul(a, b, tmp);
   gf_mod(tmp, m, c);
   gf_zero(tmp);
}

/* B = 1/A mod M */
void gf_invmod(gf_intp A, gf_intp M, gf_intp B)
{
  gf_int m, n, p0, p1, p2, r, q, tmp;

  /* put all variables in known setup state */
  gf_zero(p0);
  gf_zero(p2);
  gf_copy(M, m);
  gf_copy(A, n);
  p0[0] = 1;
  gf_div(m, n, p1, r);
  gf_copy(p1, q);

  /* loop until r == 0 */
  while (!gf_iszero(r)) {
     gf_copy(n, m);
     gf_copy(r, n);
     gf_div(m, n, q, r);
     gf_mul(q, p1, tmp);
     gf_add(tmp, p0, p2);
     gf_copy(p1, p0);
     gf_copy(p2, p1);
  }
  gf_copy(p0, B);
  gf_zero(p0);
}

/* find a square root modulo a prime.  Note the number of 
 * elements is 2^k - 1, so we must square k-2 times to get the
 * square root.. 
 */
void gf_sqrt(gf_intp a, gf_intp M, gf_intp b)
{
   int k;
   k = gf_deg(M)-2;
   gf_copy(a, b);
   while (k--)
      gf_mulmod(b, b, M, b);
}

/* c = gcd(A,B) */
void gf_gcd(gf_intp A, gf_intp B, gf_intp c)
{
   gf_int a, b, r;
   int n;

   gf_add(A, B, r);
   n = gf_deg(r);
   if (gf_deg(A) > n) {
      gf_copy(A, a);
      gf_copy(B, b);
   } else {
      gf_copy(A, b);
      gf_copy(B, a);
   }

   do {
      gf_mod(a, b, r);
      gf_copy(b, a);
      gf_copy(r, b);
   } while (!gf_iszero(r));
   gf_copy(a, c);
   gf_zero(a);
   gf_zero(b);
}

/* returns non-zero if 'a' is irreducible */
int gf_is_prime(gf_intp a)
{
   gf_int u, tmp;
   int m, n;

   gf_zero(u);
   u[0] = 2;			/* u(x) = x */
   m = gf_deg(a);
   for (n = 0; n < (m/2); n++) { 
       gf_mulmod(u, u, a, u);   /* u(x) = u(x)^2 mod a(x) */
       gf_copy(u, tmp);
       tmp[0] ^= 2;		/* tmp(x) = u(x) - x */
       gf_gcd(tmp, a, tmp);     /* tmp(x) = gcd(a(x), u(x) - x) */
       if (!gf_isone(tmp)) {
          return 0;
       }
   }
   return 1;
}  

/* returns bytes required to store a gf_int */
int gf_size(gf_intp a)
{
   int n;

   n = gf_deg(a);
   if (n == -1) {
      return 4;
   }
   n = n + (32 - (n&31));
   return n/8;
}

/* store a gf_int */
void gf_toraw(gf_intp a, unsigned char *dst)
{
   int x, n;
   n = gf_size(a)/4;
   for (x = 0; x < n; x++) {
       STORE32L(a[x], dst);
       dst += 4;
   }
}

/* read a gf_int (len == in bytes) */
void gf_readraw(gf_intp a, unsigned char *str, int len)
{
   int x;
   gf_zero(a);
   for (x = 0; x < len/4; x++) {
       LOAD32L(a[x], str);
       str += 4;
   }
}

#endif


