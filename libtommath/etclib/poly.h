/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is library that provides for multiple-precision 
 * integer arithmetic as well as number theoretic functionality.
 *
 * This file "poly.h" provides GF(p^k) functionality on top of the 
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

#ifndef POLY_H_
#define POLY_H_

#include "bn.h"

/* a mp_poly is basically a derived "class" of a mp_int
 * it uses the same technique of growing arrays via 
 * used/alloc parameters except the base unit or "digit"
 * is in fact a mp_int.  These hold the coefficients
 * of the polynomial 
 */
typedef struct {
    int    used,    /* coefficients used */
           alloc;   /* coefficients allocated (and initialized) */
    mp_int *co,     /* coefficients */
           cha;     /* characteristic */
    
} mp_poly;


#define MP_POLY_PREC     16             /* default coefficients allocated */

/* init a poly */
int mp_poly_init(mp_poly *a, mp_int *cha);

/* init a poly of a given (size) degree  */
int mp_poly_init_size(mp_poly *a, mp_int *cha, int size);

/* copy, b = a */
int mp_poly_copy(mp_poly *a, mp_poly *b);

/* init from a copy, a = b */
int mp_poly_init_copy(mp_poly *a, mp_poly *b);

/* free a poly from ram */
void mp_poly_clear(mp_poly *a);

/* exchange two polys */
void mp_poly_exch(mp_poly *a, mp_poly *b);

/* ---> Basic Arithmetic <--- */

/* add two polynomials, c(x) = a(x) + b(x) */
int mp_poly_add(mp_poly *a, mp_poly *b, mp_poly *c);

/* subtracts two polynomials, c(x) = a(x) - b(x) */
int mp_poly_sub(mp_poly *a, mp_poly *b, mp_poly *c);

/* multiplies two polynomials, c(x) = a(x) * b(x) */
int mp_poly_mul(mp_poly *a, mp_poly *b, mp_poly *c);



#endif

