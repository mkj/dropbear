/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is library that provides for multiple-precision 
 * integer arithmetic as well as number theoretic functionality.
 *
 * This file "poly.c" provides GF(p^k) functionality on top of the 
 * libtommath library.
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
#include "poly.h"

#undef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#undef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))

static void s_free(mp_poly *a)
{
   int k;
   for (k = 0; k < a->alloc; k++) {
       mp_clear(&(a->co[k]));
   }
}

static int s_setup(mp_poly *a, int low, int high)
{
   int res, k, j;
   for (k = low; k < high; k++) {
       if ((res = mp_init(&(a->co[k]))) != MP_OKAY) {
          for (j = low; j < k; j++) {
             mp_clear(&(a->co[j]));
          }
          return MP_MEM;
       }
   }
   return MP_OKAY;
}   

int mp_poly_init(mp_poly *a, mp_int *cha)
{
   return mp_poly_init_size(a, cha, MP_POLY_PREC);
}

/* init a poly of a given (size) degree */
int mp_poly_init_size(mp_poly *a, mp_int *cha, int size)
{
   int res;
   
   /* allocate array of mp_ints for coefficients */
   a->co = malloc(size * sizeof(mp_int));
   if (a->co == NULL) {
      return MP_MEM;
   }
   a->used  = 0;
   a->alloc = size;
   
   /* now init the range */
   if ((res = s_setup(a, 0, size)) != MP_OKAY) {
      free(a->co);
      return res;
   }
   
   /* copy characteristic */
   if ((res = mp_init_copy(&(a->cha), cha)) != MP_OKAY) {
      s_free(a);
      free(a->co);
      return res;
   }
   
   /* return ok at this point */
   return MP_OKAY;
}

/* grow the size of a poly */
static int mp_poly_grow(mp_poly *a, int size)
{
  int res;
  
  if (size > a->alloc) {
     /* resize the array of coefficients */
     a->co = realloc(a->co, sizeof(mp_int) * size);
     if (a->co == NULL) {
        return MP_MEM;
     }
     
     /* now setup the coefficients */
     if ((res = s_setup(a, a->alloc, a->alloc + size)) != MP_OKAY) {
        return res;
     }
     
     a->alloc += size;
  }
  return MP_OKAY;
}

/* copy, b = a */
int mp_poly_copy(mp_poly *a, mp_poly *b)
{
   int res, k;
   
   /* resize b */
   if ((res = mp_poly_grow(b, a->used)) != MP_OKAY) {
      return res;
   }
   
   /* now copy the used part */
   b->used = a->used;
   
   /* now the cha */
   if ((res = mp_copy(&(a->cha), &(b->cha))) != MP_OKAY) {
      return res;
   }
   
   /* now all the coefficients */
   for (k = 0; k < b->used; k++) {
       if ((res = mp_copy(&(a->co[k]), &(b->co[k]))) != MP_OKAY) {
          return res;
       }
   }
   
   /* now zero the top */
   for (k = b->used; k < b->alloc; k++) {
       mp_zero(&(b->co[k]));
   }
   
   return MP_OKAY;
}

/* init from a copy, a = b */
int mp_poly_init_copy(mp_poly *a, mp_poly *b)
{
   int res;
   
   if ((res = mp_poly_init(a, &(b->cha))) != MP_OKAY) {
      return res;
   }
   return mp_poly_copy(b, a);
}

/* free a poly from ram */
void mp_poly_clear(mp_poly *a)
{
   s_free(a);
   mp_clear(&(a->cha));
   free(a->co);
   
   a->co = NULL;
   a->used = a->alloc = 0;
}

/* exchange two polys */
void mp_poly_exch(mp_poly *a, mp_poly *b)
{
   mp_poly t;
   t = *a; *a = *b; *b = t;
}

/* clamp the # of used digits */
static void mp_poly_clamp(mp_poly *a)
{
   while (a->used > 0 && mp_cmp_d(&(a->co[a->used]), 0) == MP_EQ) --(a->used);
}  

/* add two polynomials, c(x) = a(x) + b(x) */
int mp_poly_add(mp_poly *a, mp_poly *b, mp_poly *c)
{
   mp_poly t, *x, *y;
   int res, k;
   
   /* ensure char's are the same */
   if (mp_cmp(&(a->cha), &(b->cha)) != MP_EQ) {
      return MP_VAL;
   }
   
   /* now figure out the sizes such that x is the 
      largest degree poly and y is less or equal in degree 
    */
   if (a->used > b->used) {
      x = a;
      y = b;
   } else {
      x = b;
      y = a;
   }
   
   /* now init the result to be a copy of the largest */
   if ((res = mp_poly_init_copy(&t, x)) != MP_OKAY) {
      return res;
   }
   
   /* now add the coeffcients of the smaller one */
   for (k = 0; k < y->used; k++) {
       if ((res = mp_addmod(&(a->co[k]), &(b->co[k]), &(a->cha), &(t.co[k]))) != MP_OKAY) {
          goto __T;
       }
   }
   
   mp_poly_clamp(&t);
   mp_poly_exch(&t, c);
   res = MP_OKAY;
       
__T:  mp_poly_clear(&t);
   return res;
}

/* subtracts two polynomials, c(x) = a(x) - b(x) */
int mp_poly_sub(mp_poly *a, mp_poly *b, mp_poly *c)
{
   mp_poly t, *x, *y;
   int res, k;
   
   /* ensure char's are the same */
   if (mp_cmp(&(a->cha), &(b->cha)) != MP_EQ) {
      return MP_VAL;
   }
   
   /* now figure out the sizes such that x is the 
      largest degree poly and y is less or equal in degree 
    */
   if (a->used > b->used) {
      x = a;
      y = b;
   } else {
      x = b;
      y = a;
   }
   
   /* now init the result to be a copy of the largest */
   if ((res = mp_poly_init_copy(&t, x)) != MP_OKAY) {
      return res;
   }
   
   /* now add the coeffcients of the smaller one */
   for (k = 0; k < y->used; k++) {
       if ((res = mp_submod(&(a->co[k]), &(b->co[k]), &(a->cha), &(t.co[k]))) != MP_OKAY) {
          goto __T;
       }
   }
   
   mp_poly_clamp(&t);
   mp_poly_exch(&t, c);
   res = MP_OKAY;
       
__T:  mp_poly_clear(&t);
   return res;
}

/* multiplies two polynomials, c(x) = a(x) * b(x) */
int mp_poly_mul(mp_poly *a, mp_poly *b, mp_poly *c)
{
   mp_poly t;
   mp_int  tt;
   int res, pa, pb, ix, iy;
   
   /* ensure char's are the same */
   if (mp_cmp(&(a->cha), &(b->cha)) != MP_EQ) {
      return MP_VAL;
   }
   
   /* degrees of a and b */
   pa = a->used;
   pb = b->used;
   
   /* now init the temp polynomial to be of degree pa+pb */
   if ((res = mp_poly_init_size(&t, &(a->cha), pa+pb)) != MP_OKAY) {
      return res;
   }
   
   /* now init our temp int */
   if ((res = mp_init(&tt)) != MP_OKAY) {
      goto __T;
   }
   
   /* now loop through all the digits */
   for (ix = 0; ix < pa; ix++) {
       for (iy = 0; iy < pb; iy++) {
          if ((res = mp_mul(&(a->co[ix]), &(b->co[iy]), &tt)) != MP_OKAY) {
             goto __TT;
          }
          if ((res = mp_addmod(&tt, &(t.co[ix+iy]), &(a->cha), &(t.co[ix+iy]))) != MP_OKAY) {
             goto __TT;
          }
       }
   }
   
   mp_poly_clamp(&t);
   mp_poly_exch(&t, c);
   res = MP_OKAY;
   
__TT: mp_clear(&tt);
__T:  mp_poly_clear(&t);
   return res;
}

