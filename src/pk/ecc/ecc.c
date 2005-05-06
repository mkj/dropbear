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
#define ECC_BUF_SIZE 160

/* max private key size */
#define ECC_MAXSIZE  66

/* This holds the key settings.  ***MUST*** be organized by size from smallest to largest. */
static const struct {
   int size;
   char *name, *prime, *B, *order, *Gx, *Gy;
} sets[] = {
#ifdef ECC160
{
   20,
   "ECC-160",
   /* prime */
   "G00000000000000000000000007",
   /* B */
   "1oUV2vOaSlWbxr6",
   /* order */
   "G0000000000004sCQUtDxaqDUN5",
   /* Gx */
   "jpqOf1BHus6Yd/pyhyVpP",
   /* Gy */
   "D/wykuuIFfr+vPyx7kQEPu8MixO",
},
#endif
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
   "400000000000000000000000000000000000BV",

   /* B */
   "21HkWGL2CxJIp",

   /* order */
   "4000000000000000000Kxnixk9t8MLzMiV264/",

   /* Gx */
   "jpqOf1BHus6Yd/pyhyVpP",

   /* Gy */
   "3FCtyo2yHA5SFjkCGbYxbOvNeChwS+j6wSIwck",
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

#if 0

/* you plug in a prime and B value and it finds a pseudo-random base point */
void ecc_find_base(void)
{
   static char *prime = "26959946667150639794667015087019630673637144422540572481103610249951";
   static char *order = "26959946667150639794667015087019637467111563745054605861463538557247";
   static char *b     = "9538957348957353489587";
   mp_int pp, p, r, B, tmp1, tmp2, tx, ty, x, y;
   char buf[4096];
   int i;

   mp_init_multi(&tx, &ty, &x, &y, &p, &pp, &r, &B, &tmp1, &tmp2, NULL);
   mp_read_radix(&p, prime, 10);
   mp_read_radix(&r, order, 10);
   mp_read_radix(&B, b, 10);

   /* get (p+1)/4 */
   mp_add_d(&p, 1, &pp);
   mp_div_2(&pp, &pp);
   mp_div_2(&pp, &pp);

   buf[0] = 0;
   do {
      printf("."); fflush(stdout);
      /* make a random value of x */
      for (i = 0; i < 16; i++) buf[i+1] = rand() & 255;
      mp_read_raw(&x, buf, 17);
      mp_copy(&x, &tx);

      /* now compute x^3 - 3x + b */
      mp_expt_d(&x, 3, &tmp1);
      mp_mul_d(&x, 3, &tmp2);
      mp_sub(&tmp1, &tmp2, &tmp1);
      mp_add(&tmp1, &B, &tmp1);
      mp_mod(&tmp1, &p, &tmp1);

      /* now compute sqrt via x^((p+1)/4) */
      mp_exptmod(&tmp1, &pp, &p, &tmp2);
      mp_copy(&tmp2, &ty);

      /* now square it */
      mp_sqrmod(&tmp2, &p, &tmp2);

      /* tmp2 should equal tmp1 */
   } while (mp_cmp(&tmp1, &tmp2));

   /* now output values in way that libtomcrypt wants */
   mp_todecimal(&p, buf);
   printf("\n\np==%s\n", buf);
   mp_tohex(&B, buf);
   printf("b==%s\n", buf);
   mp_todecimal(&r, buf);
   printf("r==%s\n", buf);
   mp_tohex(&tx, buf);
   printf("Gx==%s\n", buf);
   mp_tohex(&ty, buf);
   printf("Gy==%s\n", buf);

   mp_clear_multi(&tx, &ty, &x, &y, &p, &pp, &r, &B, &tmp1, &tmp2, NULL);
}
 
#endif

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

static int ecc_map(ecc_point *P, mp_int *modulus, mp_int *mu)
{
   mp_int t1, t2;
   int err;

   if ((err = mp_init_multi(&t1, &t2, NULL)) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   /* get 1/z */
   if ((err = mp_invmod(&P->z, modulus, &t1)) != MP_OKAY)                   { goto error; }
 
   /* get 1/z^2 and 1/z^3 */
   if ((err = mp_sqr(&t1, &t2)) != MP_OKAY)                        { goto error; }
   if ((err = mp_reduce(&t2, modulus, mu)) != MP_OKAY)             { goto error; }
   if ((err = mp_mul(&t1, &t2, &t1)) != MP_OKAY)                   { goto error; }
   if ((err = mp_reduce(&t1, modulus, mu)) != MP_OKAY)             { goto error; }

   /* multiply against x/y */
   if ((err = mp_mul(&P->x, &t2, &P->x)) != MP_OKAY)               { goto error; }
   if ((err = mp_reduce(&P->x, modulus, mu)) != MP_OKAY)           { goto error; }
   if ((err = mp_mul(&P->y, &t1, &P->y)) != MP_OKAY)               { goto error; }
   if ((err = mp_reduce(&P->y, modulus, mu)) != MP_OKAY)           { goto error; }
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
static int dbl_point(ecc_point *P, ecc_point *R, mp_int *modulus, mp_int *mu)
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
   if ((err = mp_reduce(&t1, modulus, mu)) != MP_OKAY)                             { goto error; }
   /* Z = Y * Z */
   if ((err = mp_mul(&R->z, &R->y, &R->z)) != MP_OKAY)                             { goto error; }
   if ((err = mp_reduce(&R->z, modulus, mu)) != MP_OKAY)                           { goto error; }
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
   if ((err = mp_reduce(&t2, modulus, mu)) != MP_OKAY)                             { goto error; }
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
   if ((err = mp_reduce(&R->y, modulus, mu)) != MP_OKAY)                           { goto error; }
   /* T2 = Y * Y */
   if ((err = mp_sqr(&R->y, &t2)) != MP_OKAY)                                      { goto error; }
   if ((err = mp_reduce(&t2, modulus, mu)) != MP_OKAY)                             { goto error; }
   /* T2 = T2/2 */
   if (mp_isodd(&t2)) {
      if ((err = mp_add(&t2, modulus, &t2)) != MP_OKAY)                            { goto error; }
   }
   if ((err = mp_div_2(&t2, &t2)) != MP_OKAY)                                      { goto error; }
   /* Y = Y * X */
   if ((err = mp_mul(&R->y, &R->x, &R->y)) != MP_OKAY)                             { goto error; }
   if ((err = mp_reduce(&R->y, modulus, mu)) != MP_OKAY)                           { goto error; }

   /* X  = T1 * T1 */
   if ((err = mp_sqr(&t1, &R->x)) != MP_OKAY)                                      { goto error; }
   if ((err = mp_reduce(&R->x, modulus, mu)) != MP_OKAY)                           { goto error; }
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
   if ((err = mp_reduce(&R->y, modulus, mu)) != MP_OKAY)                           { goto error; }
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
static int add_point(ecc_point *P, ecc_point *Q, ecc_point *R, mp_int *modulus, mp_int *mu)
{
   mp_int t1, t2, x, y, z;
   int err;

   if ((err = mp_init_multi(&t1, &t2, &x, &y, &z, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   if ((err = mp_copy(&P->x, &x)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_copy(&P->y, &y)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_copy(&P->z, &z)) != MP_OKAY)                                   { goto error; }

   /* if Z' != 1 */
   if (mp_cmp_d(&Q->z, 1) != MP_EQ) {
      /* T1 = Z' * Z' */
      if ((err = mp_sqr(&Q->z, &t1)) != MP_OKAY)                                { goto error; }
      if ((err = mp_reduce(&t1, modulus, mu)) != MP_OKAY)                       { goto error; }
      /* X = X * T1 */
      if ((err = mp_mul(&t1, &x, &x)) != MP_OKAY)                               { goto error; }
      if ((err = mp_reduce(&x, modulus, mu)) != MP_OKAY)                        { goto error; }
      /* T1 = Z' * T1 */
      if ((err = mp_mul(&Q->z, &t1, &t1)) != MP_OKAY)                           { goto error; }
      if ((err = mp_reduce(&t1, modulus, mu)) != MP_OKAY)                       { goto error; }
      /* Y = Y * T1 */
      if ((err = mp_mul(&t1, &y, &y)) != MP_OKAY)                               { goto error; }
      if ((err = mp_reduce(&y, modulus, mu)) != MP_OKAY)                        { goto error; }
   }

   /* T1 = Z*Z */
   if ((err = mp_sqr(&z, &t1)) != MP_OKAY)                                      { goto error; }
   if ((err = mp_reduce(&t1, modulus, mu)) != MP_OKAY)                          { goto error; }
   /* T2 = X' * T1 */
   if ((err = mp_mul(&Q->x, &t1, &t2)) != MP_OKAY)                              { goto error; }
   if ((err = mp_reduce(&t2, modulus, mu)) != MP_OKAY)                          { goto error; }
   /* T1 = Z * T1 */
   if ((err = mp_mul(&z, &t1, &t1)) != MP_OKAY)                                 { goto error; }
   if ((err = mp_reduce(&t1, modulus, mu)) != MP_OKAY)                          { goto error; }
   /* T1 = Y' * T1 */
   if ((err = mp_mul(&Q->y, &t1, &t1)) != MP_OKAY)                              { goto error; }
   if ((err = mp_reduce(&t1, modulus, mu)) != MP_OKAY)                          { goto error; }

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
      if ((err = mp_reduce(&z, modulus, mu)) != MP_OKAY)                        { goto error; }
   }
   /* Z = Z * X */
   if ((err = mp_mul(&z, &x, &z)) != MP_OKAY)                                   { goto error; }
   if ((err = mp_reduce(&z, modulus, mu)) != MP_OKAY)                           { goto error; }

   /* T1 = T1 * X  */
   if ((err = mp_mul(&t1, &x, &t1)) != MP_OKAY)                                 { goto error; }
   if ((err = mp_reduce(&t1, modulus, mu)) != MP_OKAY)                          { goto error; }
   /* X = X * X */
   if ((err = mp_sqr(&x, &x)) != MP_OKAY)                                       { goto error; }
   if ((err = mp_reduce(&x, modulus, mu)) != MP_OKAY)                           { goto error; }
   /* T2 = T2 * x */
   if ((err = mp_mul(&t2, &x, &t2)) != MP_OKAY)                                 { goto error; }
   if ((err = mp_reduce(&t2, modulus, mu)) != MP_OKAY)                          { goto error; }
   /* T1 = T1 * X  */
   if ((err = mp_mul(&t1, &x, &t1)) != MP_OKAY)                                 { goto error; }
   if ((err = mp_reduce(&t1, modulus, mu)) != MP_OKAY)                          { goto error; }
 
   /* X = Y*Y */
   if ((err = mp_sqr(&y, &x)) != MP_OKAY)                                       { goto error; }
   if ((err = mp_reduce(&x, modulus, mu)) != MP_OKAY)                           { goto error; }
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
   if ((err = mp_reduce(&t2, modulus, mu)) != MP_OKAY)                          { goto error; }
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
static int ecc_mulmod(mp_int *k, ecc_point *G, ecc_point *R, mp_int *modulus)
{
   ecc_point *tG, *M[8];
   int        i, j, err;
   mp_int     mu;
   mp_digit   buf;
   int        first, bitbuf, bitcpy, bitcnt, mode, digidx;

  /* init barrett reduction */
  if ((err = mp_init(&mu)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
  }
  if ((err = mp_reduce_setup(&mu, modulus)) != MP_OKAY) {
      mp_clear(&mu);
      return mpi_to_ltc_error(err);
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

   /* tG = G */
   if ((err = mp_copy(&G->x, &tG->x)) != MP_OKAY)                             { goto error; }
   if ((err = mp_copy(&G->y, &tG->y)) != MP_OKAY)                             { goto error; }
   if ((err = mp_copy(&G->z, &tG->z)) != MP_OKAY)                             { goto error; }
   
   /* calc the M tab, which holds kG for k==8..15 */
   /* M[0] == 8G */
   if ((err = dbl_point(G, M[0], modulus, &mu)) != CRYPT_OK)                  { goto done; }
   if ((err = dbl_point(M[0], M[0], modulus, &mu)) != CRYPT_OK)               { goto done; }
   if ((err = dbl_point(M[0], M[0], modulus, &mu)) != CRYPT_OK)               { goto done; }

   /* now find (8+k)G for k=1..7 */
   for (j = 9; j < 16; j++) {
       if ((err = add_point(M[j-9], G, M[j-8], modulus, &mu)) != CRYPT_OK)    { goto done; }
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

     /* grab the next msb from the multiplicand */
     i = (buf >> (DIGIT_BIT - 1)) & 1;
     buf <<= 1;

     /* skip leading zero bits */
     if (mode == 0 && i == 0) {
        continue;
     }

     /* if the bit is zero and mode == 1 then we double */
     if (mode == 1 && i == 0) {
        if ((err = dbl_point(R, R, modulus, &mu)) != CRYPT_OK)                { goto done; }
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
           if ((err = dbl_point(R, R, modulus, &mu)) != CRYPT_OK)             { goto done; }
         }

         /* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranteed */
         if ((err = add_point(R, M[bitbuf-8], R, modulus, &mu)) != CRYPT_OK)  { goto done; }
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
          if ((err = dbl_point(R, R, modulus, &mu)) != CRYPT_OK)               { goto done; }
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
            if ((err = add_point(R, tG, R, modulus, &mu)) != CRYPT_OK)         { goto done; }
         }
       }
     }
   }

   /* map R back from projective space */
   err = ecc_map(R, modulus, &mu);
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   del_point(tG);
   for (i = 0; i < 8; i++) {
       del_point(M[i]);
   }
   mp_clear(&mu);
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
       if ((err = ecc_mulmod(&order, G, GG, &modulus)) != CRYPT_OK)                 { goto done; }
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
   if ((err = ecc_mulmod(&key->k, base, &key->pubkey, &prime)) != CRYPT_OK)             { goto LBL_ERR; }
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

static int compress_y_point(ecc_point *pt, int idx, int *result)
{
   mp_int tmp, tmp2, p;
   int err;

   LTC_ARGCHK(pt     != NULL);
   LTC_ARGCHK(result != NULL);

   if ((err = mp_init_multi(&tmp, &tmp2, &p, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* get x^3 - 3x + b */
   if ((err = mp_read_radix(&p, (char *)sets[idx].B, 64)) != MP_OKAY) { goto error; } /* p = B */
   if ((err = mp_expt_d(&pt->x, 3, &tmp)) != MP_OKAY)                 { goto error; } /* tmp = pX^3  */
   if ((err = mp_mul_d(&pt->x, 3, &tmp2)) != MP_OKAY)                 { goto error; } /* tmp2 = 3*pX^3 */
   if ((err = mp_sub(&tmp, &tmp2, &tmp)) != MP_OKAY)                  { goto error; } /* tmp = tmp - tmp2 */
   if ((err = mp_add(&tmp, &p, &tmp)) != MP_OKAY)                     { goto error; } /* tmp = tmp + p */
   if ((err = mp_read_radix(&p, (char *)sets[idx].prime, 64)) != MP_OKAY)  { goto error; } /* p = prime */
   if ((err = mp_mod(&tmp, &p, &tmp)) != MP_OKAY)                     { goto error; } /* tmp = tmp mod p */

   /* now find square root */
   if ((err = mp_add_d(&p, 1, &tmp2)) != MP_OKAY)                     { goto error; } /* tmp2 = p + 1 */
   if ((err = mp_div_2d(&tmp2, 2, &tmp2, NULL)) != MP_OKAY)           { goto error; } /* tmp2 = (p+1)/4 */
   if ((err = mp_exptmod(&tmp, &tmp2, &p, &tmp)) != MP_OKAY)          { goto error; } /* tmp  = (x^3 - 3x + b)^((p+1)/4) mod p */

   /* if tmp equals the y point give a 0, otherwise 1 */
   if (mp_cmp(&tmp, &pt->y) == 0) {
      *result = 0;
   } else {
      *result = 1;
   }

   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&p, &tmp, &tmp2, NULL);
   return err;
}

static int expand_y_point(ecc_point *pt, int idx, int result)
{
   mp_int tmp, tmp2, p;
   int err;

   LTC_ARGCHK(pt != NULL);

   if ((err = mp_init_multi(&tmp, &tmp2, &p, NULL)) != MP_OKAY) {
      return CRYPT_MEM;
   }

   /* get x^3 - 3x + b */
   if ((err = mp_read_radix(&p, (char *)sets[idx].B, 64)) != MP_OKAY) { goto error; } /* p = B */
   if ((err = mp_expt_d(&pt->x, 3, &tmp)) != MP_OKAY)                 { goto error; } /* tmp = pX^3 */
   if ((err = mp_mul_d(&pt->x, 3, &tmp2)) != MP_OKAY)                 { goto error; } /* tmp2 = 3*pX^3 */
   if ((err = mp_sub(&tmp, &tmp2, &tmp)) != MP_OKAY)                  { goto error; } /* tmp = tmp - tmp2 */
   if ((err = mp_add(&tmp, &p, &tmp)) != MP_OKAY)                     { goto error; } /* tmp = tmp + p */
   if ((err = mp_read_radix(&p, (char *)sets[idx].prime, 64)) != MP_OKAY)  { goto error; } /* p = prime */
   if ((err = mp_mod(&tmp, &p, &tmp)) != MP_OKAY)                     { goto error; } /* tmp = tmp mod p */

   /* now find square root */
   if ((err = mp_add_d(&p, 1, &tmp2)) != MP_OKAY)                     { goto error; } /* tmp2 = p + 1 */
   if ((err = mp_div_2d(&tmp2, 2, &tmp2, NULL)) != MP_OKAY)           { goto error; } /* tmp2 = (p+1)/4 */
   if ((err = mp_exptmod(&tmp, &tmp2, &p, &tmp)) != MP_OKAY)          { goto error; } /* tmp  = (x^3 - 3x + b)^((p+1)/4) mod p */

   /* if result==0, then y==tmp, otherwise y==p-tmp */
   if (result == 0) {
      if ((err = mp_copy(&tmp, &pt->y) != MP_OKAY))                   { goto error; }
   } else {
      if ((err = mp_sub(&p, &tmp, &pt->y) != MP_OKAY))                { goto error; }
   }

   err = CRYPT_OK;
   goto done;
error:
   err = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&p, &tmp, &tmp2, NULL);
   return err;
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
   unsigned long y, z;
   int cp, err;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);
   
   /* can we store the static header?  */
   if (*outlen < (PACKET_SIZE + 3)) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* type valid? */
   if (key->type != PK_PRIVATE && type == PK_PRIVATE) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   /* output type and magic byte */
   y = PACKET_SIZE;
   out[y++] = (unsigned char)type;
   out[y++] = (unsigned char)sets[key->idx].size;

   /* output x coordinate */
   OUTPUT_BIGNUM(&(key->pubkey.x), out, y, z);

   /* compress y and output it  */
   if ((err = compress_y_point(&key->pubkey, key->idx, &cp)) != CRYPT_OK) {
      return err;
   }
   out[y++] = (unsigned char)cp;

   if (type == PK_PRIVATE) {
      OUTPUT_BIGNUM(&key->k, out, y, z);
   }

   /* store header */
   packet_store_header(out, PACKET_SECT_ECC, PACKET_SUB_KEY);
   *outlen = y;

   return CRYPT_OK;
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
   unsigned long x, y, s;
   int err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   /* check length */
   if ((3+PACKET_SIZE) > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   /* check type */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_ECC, PACKET_SUB_KEY)) != CRYPT_OK) {
      return err;
   }

   /* init key */
   if (mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }

   y = PACKET_SIZE;
   key->type = (int)in[y++];
   s = (unsigned long)in[y++];

   for (x = 0; (s > (unsigned long)sets[x].size) && (sets[x].size != 0); x++);
   if (sets[x].size == 0) {
      err = CRYPT_INVALID_KEYSIZE;
      goto error;
   }
   key->idx = (int)x;

   /* type check both values */
   if ((key->type != PK_PUBLIC) && (key->type != PK_PRIVATE))  {
      err = CRYPT_INVALID_PACKET;
      goto error;
   }

   /* is the key idx valid? */
   if (is_valid_idx(key->idx) != 1) {
      err = CRYPT_INVALID_PACKET;
      goto error;
   }

   /* load x coordinate */
   INPUT_BIGNUM(&key->pubkey.x, in, x, y, inlen);

   /* load y */
   x = (unsigned long)in[y++];
   if ((err = expand_y_point(&key->pubkey, key->idx, (int)x)) != CRYPT_OK) {
       goto error;
   }

   if (key->type == PK_PRIVATE) {
      /* load private key */
      INPUT_BIGNUM(&key->k, in, x, y, inlen);
   }

   /* eliminate private key if public */
   if (key->type == PK_PUBLIC) {
      mp_clear(&key->k);
   }

   /* z is always 1 */
   mp_set(&key->pubkey.z, 1);

   return CRYPT_OK;
error:
   mp_clear_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, NULL);
   return err;
}

/**
  Create an ECC shared secret between two keys
  @param private_key      The private ECC key
  @param public_key       The public key
  @param out              [out] Destination of the shared secret
  @param outlen           [in/out] The max size and resulting size of the shared secret
  @return CRYPT_OK if successful
*/
int ecc_shared_secret(ecc_key *private_key, ecc_key *public_key,
                      unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y;
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

   if ((err = mp_read_radix(&prime, (char *)sets[private_key->idx].prime, 64)) != MP_OKAY)   { goto error; }
   if ((err = ecc_mulmod(&private_key->k, &public_key->pubkey, result, &prime)) != CRYPT_OK) { goto done1; }

   x = (unsigned long)mp_unsigned_bin_size(&result->x);
   y = (unsigned long)mp_unsigned_bin_size(&result->y);

   if (*outlen < (x+y)) {
      err = CRYPT_BUFFER_OVERFLOW;
      goto done1;
   }
   *outlen = x+y;
   if ((err = mp_to_unsigned_bin(&result->x, out))   != MP_OKAY)          { goto error; }
   if ((err = mp_to_unsigned_bin(&result->y, out+x)) != MP_OKAY)          { goto error; }

   err = CRYPT_OK;
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


