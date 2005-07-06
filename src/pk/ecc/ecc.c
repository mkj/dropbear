/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */

/* Implements ECC over Z/pZ for curve y^2 = x^3 - 3x + b
 *
 * All curves taken from NIST recommendation paper of July 1999
 * Available at http://csrc.nist.gov/cryptval/dss.htm
 */
#include "tomcrypt.h"

/**
  @file ecc.c
  ECC Crypto, Tom St Denis
*/  

#ifdef MECC

/* size of our temp buffers for exported keys */
#define ECC_BUF_SIZE 256

/* max private key size */
#define ECC_MAXSIZE  66

/* This holds the key settings.  ***MUST*** be organized by size from smallest to largest. */
static const struct {
   int size;
   char *name, *prime, *B, *order, *Gx, *Gy;
} sets[] = {
#ifdef ECC192
{
    24,
   "ECC-192",
   /* prime */
   "/////////////////////l//////////",

   /* B */
   "P2456UMSWESFf+chSYGmIVwutkp1Hhcn",

   /* order */
   "////////////////cTxuDXHhoR6qqYWn",

   /* Gx */
   "68se3h0maFPylo3hGw680FJ/2ls2/n0I",

   /* Gy */
   "1nahbV/8sdXZ417jQoJDrNFvTw4UUKWH"
},
#endif
#ifdef ECC224
{
   28,
   "ECC-224",

   /* prime */
   "3/////////////////////0000000000000001",

   /* B */
   "2q1Gg530Ipg/L1CbPGHB2trx/OkYSBEKCZLV+q",

   /* order */
   "3//////////////////nQYuBZmFXFTAKLSN2ez",

   /* Gx */
   "2t3WozQxI/Vp8JaBbA0y7JLi8H8ZGoWDOHN1qX",


   /* Gy */
   "2zDsE8jVSZ+qmYt+RDGtMWMWT7P4JLWPc507uq",
},
#endif
#ifdef ECC256
{
   32,
   "ECC-256",
   /* Prime */
   "F////y000010000000000000000////////////////",

   /* B */
   "5h6DTYgEfFdi+kzLNQOXhnb7GQmp5EmzZlEF3udqc1B",

   /* Order */
   "F////y00000//////////+yvlgjfnUUXFEvoiByOoLH",

   /* Gx */
   "6iNqVBXB497+BpcvMEaGF9t0ts1BUipeFIXEKNOcCAM",

   /* Gy */
   "4/ZGkB+6d+RZkVhIdmFdXOhpZDNQp5UpiksG6Wtlr7r"
},
#endif
#ifdef ECC384
{
   48,
   "ECC-384",
   /* prime */
   "//////////////////////////////////////////x/////00000000003/"
   "////",

   /* B */
   "ip4lf+8+v+IOZWLhu/Wj6HWTd6x+WK4I0nG8Zr0JXrh6LZcDYYxHdIg5oEtJ"
   "x2hl",

   /* Order */
   "////////////////////////////////nsDDWVGtBTzO6WsoIB2dUkpi6MhC"
   "nIbp",

   /* Gx and Gy */
   "geVA8hwB1JUEiSSUyo2jT6uTEsABfvkOMVT1u89KAZXL0l9TlrKfR3fKNZXo"
   "TWgt",

   "DXVUIfOcB6zTdfY/afBSAVZq7RqecXHywTen4xNmkC0AOB7E7Nw1dNf37NoG"
   "wWvV"
},
#endif
#ifdef ECC521
{
   65,
   "ECC-521",
   /* prime */
   "V///////////////////////////////////////////////////////////"
   "///////////////////////////",

   /* B */
   "56LFhbXZXoQ7vAQ8Q2sXK3kejfoMvcp5VEuj8cHZl49uLOPEL7iVfDx5bB0l"
   "JknlmSrSz+8FImqyUz57zHhK3y0",

   /* Order */
   "V//////////////////////////////////////////+b66XuE/BvPhVym1I"
   "FS9fT0xjScuYPn7hhjljnwHE6G9",

   /* Gx and Gy */
   "CQ5ZWQt10JfpPu+osOZbRH2d6I1EGK/jI7uAAzWQqqzkg5BNdVlvrae/Xt19"
   "wB/gDupIBF1XMf2c/b+VZ72vRrc",

   "HWvAMfucZl015oANxGiVHlPcFL4ILURH6WNhxqN9pvcB9VkSfbUz2P0nL2v0"
   "J+j1s4rF726edB2G8Y+b7QVqMPG",
},
#endif
{
   0,
   NULL, NULL, NULL, NULL, NULL, NULL
}
};

static int is_valid_idx(int n)
{
   int x;

   for (x = 0; sets[x].size != 0; x++);
   if ((n < 0) || (n >= x)) {
      return 0;
   }
   return 1;
}

static ecc_point *new_point(void)
{
   ecc_point *p;
   p = XMALLOC(sizeof(ecc_point));
   if (p == NULL) {
      return NULL;
   }
   if (mp_init_multi(&p->x, &p->y, &p->z, NULL) != MP_OKAY) {
      XFREE(p);
      return NULL;
   }
   return p;
}

static void del_point(ecc_point *p)
{
   /* prevents free'ing null arguments */
   if (p != NULL) {
      mp_clear_multi(&p->x, &p->y, &p->z, NULL);
      XFREE(p);
   }
}

static int ecc_map(ecc_point *P, mp_int *modulus, mp_digit mp)
{
   mp_int t1, t2;
   int err;

   if ((err = mp_init_multi(&t1, &t2, NULL)) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   /* first map z back to normal */
   if ((err = mp_montgomery_reduce(&P->z, modulus, mp)) != MP_OKAY)           { goto error; }

   /* get 1/z */
   if ((err = mp_invmod(&P->z, modulus, &t1)) != MP_OKAY)                     { goto error; }
 
   /* get 1/z^2 and 1/z^3 */
   if ((err = mp_sqr(&t1, &t2)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_mod(&t2, modulus, &t2)) != MP_OKAY)                          { goto error; }
   if ((err = mp_mul(&t1, &t2, &t1)) != MP_OKAY)                              { goto error; }
   if ((err = mp_mod(&t1, modulus, &t1)) != MP_OKAY)                          { goto error; }

   /* multiply against x/y */
   if ((err = mp_mul(&P->x, &t2, &P->x)) != MP_OKAY)                          { goto error; }
   if ((err = mp_montgomery_reduce(&P->x, modulus, mp)) != MP_OKAY)           { goto error; }
   if ((err = mp_mul(&P->y, &t1, &P->y)) != MP_OKAY)                          { goto error; }
   if ((err = mp_montgomery_reduce(&P->y, modulus, mp)) != MP_OKAY)           { goto error; }
   mp_set(&P->z, 1);

   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&t1, &t2, NULL);
   return err;

}

/* double a point R = 2P, R can be P*/
static int dbl_point(ecc_point *P, ecc_point *R, mp_int *modulus, mp_digit mp)
{
   mp_int t1, t2;
   int err;

   if ((err = mp_init_multi(&t1, &t2, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   if ((err = mp_copy(&P->x, &R->x)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_copy(&P->y, &R->y)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_copy(&P->z, &R->z)) != MP_OKAY)                                   { goto error; }

   /* t1 = Z * Z */
   if ((err = mp_sqr(&R->z, &t1)) != MP_OKAY)                                      { goto error; }
   if ((err = mp_montgomery_reduce(&t1, modulus, mp)) != MP_OKAY)                  { goto error; }
   /* Z = Y * Z */
   if ((err = mp_mul(&R->z, &R->y, &R->z)) != MP_OKAY)                             { goto error; }
   if ((err = mp_montgomery_reduce(&R->z, modulus, mp)) != MP_OKAY)                { goto error; }
   /* Z = 2Z */
   if ((err = mp_mul_2(&R->z, &R->z)) != MP_OKAY)                                  { goto error; }
   if (mp_cmp(&R->z, modulus) != MP_LT) {
      if ((err = mp_sub(&R->z, modulus, &R->z)) != MP_OKAY)                        { goto error; }
   }

   /* T2 = X - T1 */
   if ((err = mp_sub(&R->x, &t1, &t2)) != MP_OKAY)                                 { goto error; }
   if (mp_cmp_d(&t2, 0) == MP_LT) {
      if ((err = mp_add(&t2, modulus, &t2)) != MP_OKAY)                            { goto error; }
   }
   /* T1 = X + T1 */
   if ((err = mp_add(&t1, &R->x, &t1)) != MP_OKAY)                                 { goto error; }
   if (mp_cmp(&t1, modulus) != MP_LT) {
      if ((err = mp_sub(&t1, modulus, &t1)) != MP_OKAY)                            { goto error; }
   }
   /* T2 = T1 * T2 */
   if ((err = mp_mul(&t1, &t2, &t2)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_montgomery_reduce(&t2, modulus, mp)) != MP_OKAY)                  { goto error; }
   /* T1 = 2T2 */
   if ((err = mp_mul_2(&t2, &t1)) != MP_OKAY)                                      { goto error; }
   if (mp_cmp(&t1, modulus) != MP_LT) {
      if ((err = mp_sub(&t1, modulus, &t1)) != MP_OKAY)                            { goto error; }
   }
   /* T1 = T1 + T2 */
   if ((err = mp_add(&t1, &t2, &t1)) != MP_OKAY)                                   { goto error; }
   if (mp_cmp(&t1, modulus) != MP_LT) {
      if ((err = mp_sub(&t1, modulus, &t1)) != MP_OKAY)                            { goto error; }
   }

   /* Y = 2Y */
   if ((err = mp_mul_2(&R->y, &R->y)) != MP_OKAY)                                  { goto error; }
   if (mp_cmp(&R->y, modulus) != MP_LT) {
      if ((err = mp_sub(&R->y, modulus, &R->y)) != MP_OKAY)                        { goto error; }
   }
   /* Y = Y * Y */
   if ((err = mp_sqr(&R->y, &R->y)) != MP_OKAY)                                    { goto error; }
   if ((err = mp_montgomery_reduce(&R->y, modulus, mp)) != MP_OKAY)                { goto error; }
   /* T2 = Y * Y */
   if ((err = mp_sqr(&R->y, &t2)) != MP_OKAY)                                      { goto error; }
   if ((err = mp_montgomery_reduce(&t2, modulus, mp)) != MP_OKAY)                  { goto error; }
   /* T2 = T2/2 */
   if (mp_isodd(&t2)) {
      if ((err = mp_add(&t2, modulus, &t2)) != MP_OKAY)                            { goto error; }
   }
   if ((err = mp_div_2(&t2, &t2)) != MP_OKAY)                                      { goto error; }
   /* Y = Y * X */
   if ((err = mp_mul(&R->y, &R->x, &R->y)) != MP_OKAY)                             { goto error; }
   if ((err = mp_montgomery_reduce(&R->y, modulus, mp)) != MP_OKAY)                { goto error; }

   /* X  = T1 * T1 */
   if ((err = mp_sqr(&t1, &R->x)) != MP_OKAY)                                      { goto error; }
   if ((err = mp_montgomery_reduce(&R->x, modulus, mp)) != MP_OKAY)                { goto error; }
   /* X = X - Y */
   if ((err = mp_sub(&R->x, &R->y, &R->x)) != MP_OKAY)                             { goto error; }
   if (mp_cmp_d(&R->x, 0) == MP_LT) {
      if ((err = mp_add(&R->x, modulus, &R->x)) != MP_OKAY)                        { goto error; }
   }
   /* X = X - Y */
   if ((err = mp_sub(&R->x, &R->y, &R->x)) != MP_OKAY)                             { goto error; }
   if (mp_cmp_d(&R->x, 0) == MP_LT) {
      if ((err = mp_add(&R->x, modulus, &R->x)) != MP_OKAY)                        { goto error; }
   }

   /* Y = Y - X */     
   if ((err = mp_sub(&R->y, &R->x, &R->y)) != MP_OKAY)                             { goto error; }
   if (mp_cmp_d(&R->y, 0) == MP_LT) {
      if ((err = mp_add(&R->y, modulus, &R->y)) != MP_OKAY)                        { goto error; }
   }
   /* Y = Y * T1 */
   if ((err = mp_mul(&R->y, &t1, &R->y)) != MP_OKAY)                               { goto error; }
   if ((err = mp_montgomery_reduce(&R->y, modulus, mp)) != MP_OKAY)                { goto error; }
   /* Y = Y - T2 */
   if ((err = mp_sub(&R->y, &t2, &R->y)) != MP_OKAY)                               { goto error; }
   if (mp_cmp_d(&R->y, 0) == MP_LT) {
      if ((err = mp_add(&R->y, modulus, &R->y)) != MP_OKAY)                        { goto error; }
   }
 
   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&t1, &t2, NULL);
   return err;
}

/* add two different points over Z/pZ, R = P + Q, note R can equal either P or Q */
static int add_point(ecc_point *P, ecc_point *Q, ecc_point *R, mp_int *modulus, mp_digit mp)
{
   mp_int t1, t2, x, y, z;
   int err;

   if ((err = mp_init_multi(&t1, &t2, &x, &y, &z, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   if ((err = mp_copy(&P->x, &x)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_copy(&P->y, &y)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_copy(&P->z, &z)) != MP_OKAY)                                   { goto error; }

      /* T1 = Z' * Z' */
      if ((err = mp_sqr(&Q->z, &t1)) != MP_OKAY)                                { goto error; }
      if ((err = mp_montgomery_reduce(&t1, modulus, mp)) != MP_OKAY)            { goto error; }
      /* X = X * T1 */
      if ((err = mp_mul(&t1, &x, &x)) != MP_OKAY)                               { goto error; }
      if ((err = mp_montgomery_reduce(&x, modulus, mp)) != MP_OKAY)             { goto error; }
      /* T1 = Z' * T1 */
      if ((err = mp_mul(&Q->z, &t1, &t1)) != MP_OKAY)                           { goto error; }
      if ((err = mp_montgomery_reduce(&t1, modulus, mp)) != MP_OKAY)            { goto error; }
      /* Y = Y * T1 */
      if ((err = mp_mul(&t1, &y, &y)) != MP_OKAY)                               { goto error; }
      if ((err = mp_montgomery_reduce(&y, modulus, mp)) != MP_OKAY)             { goto error; }

   /* T1 = Z*Z */
   if ((err = mp_sqr(&z, &t1)) != MP_OKAY)                                      { goto error; }
   if ((err = mp_montgomery_reduce(&t1, modulus, mp)) != MP_OKAY)               { goto error; }
   /* T2 = X' * T1 */
   if ((err = mp_mul(&Q->x, &t1, &t2)) != MP_OKAY)                              { goto error; }
   if ((err = mp_montgomery_reduce(&t2, modulus, mp)) != MP_OKAY)               { goto error; }
   /* T1 = Z * T1 */
   if ((err = mp_mul(&z, &t1, &t1)) != MP_OKAY)                                 { goto error; }
   if ((err = mp_montgomery_reduce(&t1, modulus, mp)) != MP_OKAY)               { goto error; }
   /* T1 = Y' * T1 */
   if ((err = mp_mul(&Q->y, &t1, &t1)) != MP_OKAY)                              { goto error; }
   if ((err = mp_montgomery_reduce(&t1, modulus, mp)) != MP_OKAY)               { goto error; }

   /* Y = Y - T1 */
   if ((err = mp_sub(&y, &t1, &y)) != MP_OKAY)                                  { goto error; }
   if (mp_cmp_d(&y, 0) == MP_LT) {
      if ((err = mp_add(&y, modulus, &y)) != MP_OKAY)                           { goto error; }
   }
   /* T1 = 2T1 */
   if ((err = mp_mul_2(&t1, &t1)) != MP_OKAY)                                   { goto error; }
   if (mp_cmp(&t1, modulus) != MP_LT) {
      if ((err = mp_sub(&t1, modulus, &t1)) != MP_OKAY)                         { goto error; }
   }
   /* T1 = Y + T1 */
   if ((err = mp_add(&t1, &y, &t1)) != MP_OKAY)                                 { goto error; }
   if (mp_cmp(&t1, modulus) != MP_LT) {
      if ((err = mp_sub(&t1, modulus, &t1)) != MP_OKAY)                         { goto error; }
   }
   /* X = X - T2 */
   if ((err = mp_sub(&x, &t2, &x)) != MP_OKAY)                                  { goto error; }
   if (mp_cmp_d(&x, 0) == MP_LT) {
      if ((err = mp_add(&x, modulus, &x)) != MP_OKAY)                           { goto error; }
   }
   /* T2 = 2T2 */
   if ((err = mp_mul_2(&t2, &t2)) != MP_OKAY)                                   { goto error; }
   if (mp_cmp(&t2, modulus) != MP_LT) {
      if ((err = mp_sub(&t2, modulus, &t2)) != MP_OKAY)                         { goto error; }
   }
   /* T2 = X + T2 */
   if ((err = mp_add(&t2, &x, &t2)) != MP_OKAY)                                 { goto error; }
   if (mp_cmp(&t2, modulus) != MP_LT) {
      if ((err = mp_sub(&t2, modulus, &t2)) != MP_OKAY)                         { goto error; }
   }

   /* if Z' != 1 */
   if (mp_cmp_d(&Q->z, 1) != MP_EQ) {
      /* Z = Z * Z' */
      if ((err = mp_mul(&z, &Q->z, &z)) != MP_OKAY)                             { goto error; }
      if ((err = mp_montgomery_reduce(&z, modulus, mp)) != MP_OKAY)             { goto error; }
   }
   /* Z = Z * X */
   if ((err = mp_mul(&z, &x, &z)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_montgomery_reduce(&z, modulus, mp)) != MP_OKAY)                { goto error; }

   /* T1 = T1 * X  */
   if ((err = mp_mul(&t1, &x, &t1)) != MP_OKAY)                                 { goto error; }
   if ((err = mp_montgomery_reduce(&t1, modulus, mp)) != MP_OKAY)               { goto error; }
   /* X = X * X */
   if ((err = mp_sqr(&x, &x)) != MP_OKAY)                                       { goto error; }
   if ((err = mp_montgomery_reduce(&x, modulus, mp)) != MP_OKAY)                { goto error; }
   /* T2 = T2 * x */
   if ((err = mp_mul(&t2, &x, &t2)) != MP_OKAY)                                 { goto error; }
   if ((err = mp_montgomery_reduce(&t2, modulus, mp)) != MP_OKAY)               { goto error; }
   /* T1 = T1 * X  */
   if ((err = mp_mul(&t1, &x, &t1)) != MP_OKAY)                                 { goto error; }
   if ((err = mp_montgomery_reduce(&t1, modulus, mp)) != MP_OKAY)               { goto error; }
 
   /* X = Y*Y */
   if ((err = mp_sqr(&y, &x)) != MP_OKAY)                                       { goto error; }
   if ((err = mp_montgomery_reduce(&x, modulus, mp)) != MP_OKAY)                { goto error; }
   /* X = X - T2 */
   if ((err = mp_sub(&x, &t2, &x)) != MP_OKAY)                                  { goto error; }
   if (mp_cmp_d(&x, 0) == MP_LT) {
      if ((err = mp_add(&x, modulus, &x)) != MP_OKAY)                           { goto error; }
   }

   /* T2 = T2 - X */
   if ((err = mp_sub(&t2, &x, &t2)) != MP_OKAY)                                 { goto error; }
   if (mp_cmp_d(&t2, 0) == MP_LT) {
      if ((err = mp_add(&t2, modulus, &t2)) != MP_OKAY)                         { goto error; }
   } 
   /* T2 = T2 - X */
   if ((err = mp_sub(&t2, &x, &t2)) != MP_OKAY)                                 { goto error; }
   if (mp_cmp_d(&t2, 0) == MP_LT) {
      if ((err = mp_add(&t2, modulus, &t2)) != MP_OKAY)                         { goto error; }
   }
   /* T2 = T2 * Y */
   if ((err = mp_mul(&t2, &y, &t2)) != MP_OKAY)                                 { goto error; }
   if ((err = mp_montgomery_reduce(&t2, modulus, mp)) != MP_OKAY)               { goto error; }
   /* Y = T2 - T1 */
   if ((err = mp_sub(&t2, &t1, &y)) != MP_OKAY)                                 { goto error; }
   if (mp_cmp_d(&y, 0) == MP_LT) {
      if ((err = mp_add(&y, modulus, &y)) != MP_OKAY)                           { goto error; }
   }
   /* Y = Y/2 */
   if (mp_isodd(&y)) {
      if ((err = mp_add(&y, modulus, &y)) != MP_OKAY)                           { goto error; }
   }
   if ((err = mp_div_2(&y, &y)) != MP_OKAY)                                     { goto error; }

   if ((err = mp_copy(&x, &R->x)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_copy(&y, &R->y)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_copy(&z, &R->z)) != MP_OKAY)                                   { goto error; }

   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&t1, &t2, &x, &y, &z, NULL);
   return err;
}

/* size of sliding window, don't change this! */
#define WINSIZE 4

/* perform R = kG where k == integer and G == ecc_point */
static int ecc_mulmod(mp_int *k, ecc_point *G, ecc_point *R, mp_int *modulus, int map)
{
   ecc_point *tG, *M[8];
   int        i, j, err;
   mp_int     mu;
   mp_digit   buf, mp;
   int        first, bitbuf, bitcpy, bitcnt, mode, digidx;

   /* init montgomery reduction */
   if ((err = mp_montgomery_setup(modulus, &mp)) != MP_OKAY) {
      return CRYPT_INVALID_ARG;
   }
   if ((err = mp_init(&mu)) != MP_OKAY) {
      return CRYPT_MEM;
   }
   if ((err = mp_montgomery_calc_normalization(&mu, modulus)) != MP_OKAY) {
      mp_clear(&mu);
      return CRYPT_INVALID_ARG;
   }

  /* alloc ram for window temps */
  for (i = 0; i < 8; i++) {
      M[i] = new_point();
      if (M[i] == NULL) {
         for (j = 0; j < i; j++) {
             del_point(M[j]);
         }
         mp_clear(&mu);
         return CRYPT_MEM;
      }
  }

   /* make a copy of G incase R==G */
   tG = new_point();
   if (tG == NULL)                                                            { err = CRYPT_MEM; goto done; }

   /* tG = G  and convert to montgomery */
   if ((err = mp_mulmod(&G->x, &mu, modulus, &tG->x)) != MP_OKAY)             { goto error; }
   if ((err = mp_mulmod(&G->y, &mu, modulus, &tG->y)) != MP_OKAY)             { goto error; }
   if ((err = mp_mulmod(&G->z, &mu, modulus, &tG->z)) != MP_OKAY)             { goto error; }
   mp_clear(&mu);
   
   /* calc the M tab, which holds kG for k==8..15 */
   /* M[0] == 8G */
   if ((err = dbl_point(tG,   M[0], modulus, mp)) != CRYPT_OK)               { goto done; }
   if ((err = dbl_point(M[0], M[0], modulus, mp)) != CRYPT_OK)               { goto done; }
   if ((err = dbl_point(M[0], M[0], modulus, mp)) != CRYPT_OK)               { goto done; }

   /* now find (8+k)G for k=1..7 */
   for (j = 9; j < 16; j++) {
       if ((err = add_point(M[j-9], tG, M[j-8], modulus, mp)) != CRYPT_OK)   { goto done; }
   }

   /* setup sliding window */
   mode   = 0;
   bitcnt = 1;
   buf    = 0;
   digidx = k->used - 1;
   bitcpy = bitbuf = 0;
   first  = 1;

   /* perform ops */
   for (;;) {
     /* grab next digit as required */
     if (--bitcnt == 0) {
       if (digidx == -1) {
          break;
       }
       buf = k->dp[digidx--];
       bitcnt = (int) DIGIT_BIT;
     }

     /* grab the next msb from the ltiplicand */
     i = (buf >> (DIGIT_BIT - 1)) & 1;
     buf <<= 1;

     /* skip leading zero bits */
     if (mode == 0 && i == 0) {
        continue;
     }

     /* if the bit is zero and mode == 1 then we double */
     if (mode == 1 && i == 0) {
        if ((err = dbl_point(R, R, modulus, mp)) != CRYPT_OK)                { goto done; }
        continue;
     }

     /* else we add it to the window */
     bitbuf |= (i << (WINSIZE - ++bitcpy));
     mode = 2;

     if (bitcpy == WINSIZE) {
       /* if this is the first window we do a simple copy */
       if (first == 1) {
          /* R = kG [k = first window] */
          if ((err = mp_copy(&M[bitbuf-8]->x, &R->x)) != MP_OKAY)             { goto error; }
          if ((err = mp_copy(&M[bitbuf-8]->y, &R->y)) != MP_OKAY)             { goto error; }
          if ((err = mp_copy(&M[bitbuf-8]->z, &R->z)) != MP_OKAY)             { goto error; }
          first = 0;
       } else {
         /* normal window */
         /* ok window is filled so double as required and add  */
         /* double first */
         for (j = 0; j < WINSIZE; j++) {
           if ((err = dbl_point(R, R, modulus, mp)) != CRYPT_OK)             { goto done; }
         }

         /* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranteed */
         if ((err = add_point(R, M[bitbuf-8], R, modulus, mp)) != CRYPT_OK)  { goto done; }
       }
       /* empty window and reset */
       bitcpy = bitbuf = 0;
       mode = 1;
    }
  }

   /* if bits remain then double/add */
   if (mode == 2 && bitcpy > 0) {
     /* double then add */
     for (j = 0; j < bitcpy; j++) {
       /* only double if we have had at least one add first */
       if (first == 0) {
          if ((err = dbl_point(R, R, modulus, mp)) != CRYPT_OK)               { goto done; }
       }

       bitbuf <<= 1;
       if ((bitbuf & (1 << WINSIZE)) != 0) {
         if (first == 1){
            /* first add, so copy */
            if ((err = mp_copy(&tG->x, &R->x)) != MP_OKAY)                     { goto error; }
            if ((err = mp_copy(&tG->y, &R->y)) != MP_OKAY)                     { goto error; }
            if ((err = mp_copy(&tG->z, &R->z)) != MP_OKAY)                     { goto error; }
            first = 0;
         } else {
            /* then add */
            if ((err = add_point(R, tG, R, modulus, mp)) != CRYPT_OK)         { goto done; }
         }
       }
     }
   }

   /* map R back from projective space */
   if (map) {
      err = ecc_map(R, modulus, mp);
   } else {
      err = CRYPT_OK;
   }

   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   del_point(tG);
   for (i = 0; i < 8; i++) {
       del_point(M[i]);
   }
   return err;
}

#undef WINSIZE

/**
  Perform on the ECC system
  @return CRYPT_OK if successful
*/
int ecc_test(void)
{
   mp_int     modulus, order;
   ecc_point  *G, *GG;
   int i, err, primality;

   if ((err = mp_init_multi(&modulus, &order, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   G   = new_point();
   GG  = new_point();
   if (G == NULL || GG == NULL) {
      mp_clear_multi(&modulus, &order, NULL);
      del_point(G);
      del_point(GG);
      return CRYPT_MEM;
   }

   for (i = 0; sets[i].size; i++) {
       #if 0
          printf("Testing %d\n", sets[i].size);
       #endif
       if ((err = mp_read_radix(&modulus, (char *)sets[i].prime, 64)) != MP_OKAY)   { goto error; }
       if ((err = mp_read_radix(&order, (char *)sets[i].order, 64)) != MP_OKAY)     { goto error; }

       /* is prime actually prime? */
       if ((err = is_prime(&modulus, &primality)) != CRYPT_OK)                      { goto done; }
       if (primality == 0) {
          err = CRYPT_FAIL_TESTVECTOR;
          goto done;
       }

       /* is order prime ? */
       if ((err = is_prime(&order, &primality)) != CRYPT_OK)                        { goto done; }
       if (primality == 0) {
          err = CRYPT_FAIL_TESTVECTOR;
          goto done;
       }

       if ((err = mp_read_radix(&G->x, (char *)sets[i].Gx, 64)) != MP_OKAY)         { goto error; }
       if ((err = mp_read_radix(&G->y, (char *)sets[i].Gy, 64)) != MP_OKAY)         { goto error; }
       mp_set(&G->z, 1);

       /* then we should have G == (order + 1)G */
       if ((err = mp_add_d(&order, 1, &order)) != MP_OKAY)                          { goto error; }
       if ((err = ecc_mulmod(&order, G, GG, &modulus, 1)) != CRYPT_OK)              { goto done; }
       if (mp_cmp(&G->x, &GG->x) != 0 || mp_cmp(&G->y, &GG->y) != 0) {
          err = CRYPT_FAIL_TESTVECTOR;
          goto done;
       }
   }
   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   del_point(GG);
   del_point(G);
   mp_clear_multi(&order, &modulus, NULL);
   return err;
}

void ecc_sizes(int *low, int *high)
{
 int i;
 LTC_ARGCHK(low  != NULL);
 LTC_ARGCHK(high != NULL);

 *low = INT_MAX;
 *high = 0;
 for (i = 0; sets[i].size != 0; i++) {
     if (sets[i].size < *low)  {
        *low  = sets[i].size;
     }
     if (sets[i].size > *high) {
        *high = sets[i].size;
     }
 }
}

/**
  Make a new ECC key 
  @param prng         An active PRNG state
  @param wprng        The index of the PRNG you wish to use
  @param keysize      The keysize for the new key (in octets from 20 to 65 bytes)
  @param key          [out] Destination of the newly created key
  @return CRYPT_OK if successful, upon error all allocated memory will be freed
*/
int ecc_make_key(prng_state *prng, int wprng, int keysize, ecc_key *key)
{
   int            x, err;
   ecc_point     *base;
   mp_int         prime;
   unsigned char *buf;

   LTC_ARGCHK(key != NULL);

   /* good prng? */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* find key size */
   for (x = 0; (keysize > sets[x].size) && (sets[x].size != 0); x++);
   keysize = sets[x].size;

   if (keysize > ECC_MAXSIZE || sets[x].size == 0) {
      return CRYPT_INVALID_KEYSIZE;
   }
   key->idx = x;

   /* allocate ram */
   base = NULL;
   buf  = XMALLOC(ECC_MAXSIZE);
   if (buf == NULL) {
      return CRYPT_MEM;
   }

   /* make up random string */
   if (prng_descriptor[wprng].read(buf, (unsigned long)keysize, prng) != (unsigned long)keysize) {
      err = CRYPT_ERROR_READPRNG;
      goto LBL_ERR2;
   }

   /* setup the key variables */
   if ((err = mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, &prime, NULL)) != MP_OKAY) {
      err = mpi_to_ltc_error(err);
      goto LBL_ERR;
   }
   base = new_point();
   if (base == NULL) {
      mp_clear_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, &prime, NULL);
      err = CRYPT_MEM;
      goto LBL_ERR;
   }

   /* read in the specs for this key */
   if ((err = mp_read_radix(&prime, (char *)sets[key->idx].prime, 64)) != MP_OKAY)      { goto error; }
   if ((err = mp_read_radix(&base->x, (char *)sets[key->idx].Gx, 64)) != MP_OKAY)       { goto error; }
   if ((err = mp_read_radix(&base->y, (char *)sets[key->idx].Gy, 64)) != MP_OKAY)       { goto error; }
   mp_set(&base->z, 1);
   if ((err = mp_read_unsigned_bin(&key->k, (unsigned char *)buf, keysize)) != MP_OKAY) { goto error; }

   /* make the public key */
   if ((err = ecc_mulmod(&key->k, base, &key->pubkey, &prime, 1)) != CRYPT_OK)          { goto LBL_ERR; }
   key->type = PK_PRIVATE;

   /* shrink key */
   if ((err = mp_shrink(&key->k)) != MP_OKAY)                                           { goto error; }
   if ((err = mp_shrink(&key->pubkey.x)) != MP_OKAY)                                    { goto error; }
   if ((err = mp_shrink(&key->pubkey.y)) != MP_OKAY)                                    { goto error; }
   if ((err = mp_shrink(&key->pubkey.z)) != MP_OKAY)                                    { goto error; }

   /* free up ram */
   err = CRYPT_OK;
   goto LBL_ERR;
error:
   err = mpi_to_ltc_error(err);
LBL_ERR:
   del_point(base);
   mp_clear(&prime);
LBL_ERR2:
#ifdef LTC_CLEAN_STACK
   zeromem(buf, ECC_MAXSIZE);
#endif

   XFREE(buf);

   return err;
}

/**
  Free an ECC key from memory
  @param key   The key you wish to free
*/
void ecc_free(ecc_key *key)
{
   LTC_ARGCHK(key != NULL);
   mp_clear_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, NULL);
}

/**
  Export an ECC key as a binary packet
  @param out     [out] Destination for the key
  @param outlen  [in/out] Max size and resulting size of the exported key
  @param type    The type of key you want to export (PK_PRIVATE or PK_PUBLIC)
  @param key     The key to export
  @return CRYPT_OK if successful
*/
int ecc_export(unsigned char *out, unsigned long *outlen, int type, ecc_key *key)
{
   int           err;
   unsigned char flags[1];
   unsigned long key_size;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);
   
   /* type valid? */
   if (key->type != PK_PRIVATE && type == PK_PRIVATE) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   if (is_valid_idx(key->idx) == 0) {
      return CRYPT_INVALID_ARG;
   }

   /* we store the NIST byte size */
   key_size = sets[key->idx].size;

   if (type == PK_PRIVATE) {
       flags[0] = 1;
       err = der_encode_sequence_multi(out, outlen,
                                 LTC_ASN1_BIT_STRING,      1UL, flags,
                                 LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
                                 LTC_ASN1_INTEGER,         1UL, &key->pubkey.x,
                                 LTC_ASN1_INTEGER,         1UL, &key->pubkey.y,
                                 LTC_ASN1_INTEGER,         1UL, &key->k,
                                 LTC_ASN1_EOL,             0UL, NULL);
   } else {
       flags[0] = 0;
       err = der_encode_sequence_multi(out, outlen,
                                 LTC_ASN1_BIT_STRING,      1UL, flags,
                                 LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
                                 LTC_ASN1_INTEGER,         1UL, &key->pubkey.x,
                                 LTC_ASN1_INTEGER,         1UL, &key->pubkey.y,
                                 LTC_ASN1_EOL,             0UL, NULL);
   }

   return err;
}

/**
  Import an ECC key from a binary packet
  @param in      The packet to import
  @param inlen   The length of the packet
  @param key     [out] The destination of the import
  @return CRYPT_OK if successful, upon error all allocated memory will be freed
*/
int ecc_import(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   unsigned long key_size;
   unsigned char flags[1];
   int           err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   /* init key */
   if (mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }

   /* find out what type of key it is */
   if ((err = der_decode_sequence_multi(in, inlen, 
                                  LTC_ASN1_BIT_STRING, 1UL, &flags,
                                  LTC_ASN1_EOL,        0UL, NULL)) != CRYPT_OK) {
      goto error;
   }


   if (flags[0] == 1) {
      /* private key */
      key->type = PK_PRIVATE;
      if ((err = der_decode_sequence_multi(in, inlen,
                                     LTC_ASN1_BIT_STRING,      1UL, flags,
                                     LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
                                     LTC_ASN1_INTEGER,         1UL, &key->pubkey.x,
                                     LTC_ASN1_INTEGER,         1UL, &key->pubkey.y,
                                     LTC_ASN1_INTEGER,         1UL, &key->k,
                                     LTC_ASN1_EOL,             0UL, NULL)) != CRYPT_OK) {
         goto error;
      }
   } else {
      /* public key */
      /* private key */
      key->type = PK_PUBLIC;
      if ((err = der_decode_sequence_multi(in, inlen,
                                     LTC_ASN1_BIT_STRING,      1UL, flags,
                                     LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
                                     LTC_ASN1_INTEGER,         1UL, &key->pubkey.x,
                                     LTC_ASN1_INTEGER,         1UL, &key->pubkey.y,
                                     LTC_ASN1_EOL,             0UL, NULL)) != CRYPT_OK) {
         goto error;
      }
   }

   /* find the idx */
   for (key->idx = 0; sets[key->idx].size && (unsigned long)sets[key->idx].size != key_size; ++key->idx);
   if (sets[key->idx].size == 0) {
      err = CRYPT_INVALID_PACKET;
      goto error;
   }

   /* set z */
   mp_set(&key->pubkey.z, 1);

   /* we're good */
   return CRYPT_OK;
error:
   mp_clear_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, NULL);
   return err;
}

/**
  Create an ECC shared secret between two keys
  @param private_key      The private ECC key
  @param public_key       The public key
  @param out              [out] Destination of the shared secret (Conforms to EC-DH from ANSI X9.63)
  @param outlen           [in/out] The max size and resulting size of the shared secret
  @return CRYPT_OK if successful
*/
int ecc_shared_secret(ecc_key *private_key, ecc_key *public_key,
                      unsigned char *out, unsigned long *outlen)
{
   unsigned long x;
   ecc_point *result;
   mp_int prime;
   int err;

   LTC_ARGCHK(private_key != NULL);
   LTC_ARGCHK(public_key  != NULL);
   LTC_ARGCHK(out         != NULL);
   LTC_ARGCHK(outlen      != NULL);

   /* type valid? */
   if (private_key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   if (is_valid_idx(private_key->idx) == 0) {
      return CRYPT_INVALID_ARG;
   }

   if (private_key->idx != public_key->idx) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   /* make new point */
   result = new_point();
   if (result == NULL) {
      return CRYPT_MEM;
   }

   if ((err = mp_init(&prime)) != MP_OKAY) {
      del_point(result);
      return mpi_to_ltc_error(err);
   }

   if ((err = mp_read_radix(&prime, (char *)sets[private_key->idx].prime, 64)) != MP_OKAY)            { goto error; }
   if ((err = ecc_mulmod(&private_key->k, &public_key->pubkey, result, &prime, 1)) != CRYPT_OK)       { goto done1; }

   x = (unsigned long)mp_unsigned_bin_size(&prime);
   if (*outlen < x) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto done1;
   }
   zeromem(out, x);
   if ((err = mp_to_unsigned_bin(&result->x, out + (x - mp_unsigned_bin_size(&result->x))))   != MP_OKAY)          { goto error; }

   err     = CRYPT_OK;
   *outlen = x;
   goto done1;
error:
   err = mpi_to_ltc_error(err);
done1:
   mp_clear(&prime);
   del_point(result);
   return err;
}

/**
  Get the size of an ECC key
  @param key    The key to get the size of 
  @return The size (octets) of the key or INT_MAX on error
*/
int ecc_get_size(ecc_key *key)
{
   LTC_ARGCHK(key != NULL);
   if (is_valid_idx(key->idx))
      return sets[key->idx].size;
   else
      return INT_MAX; /* large value known to cause it to fail when passed to ecc_make_key() */
}

#include "ecc_sys.c"

#endif



/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc.c,v $ */
/* $Revision: 1.20 $ */
/* $Date: 2005/06/14 20:42:28 $ */
