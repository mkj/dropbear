
/* ---- GF(2^w) polynomial basis ---- */
#ifdef GF
#define   LSIZE    32   /* handle upto 1024-bit GF numbers */

typedef unsigned long gf_int[LSIZE];
typedef unsigned long *gf_intp;

extern void gf_copy(gf_intp a, gf_intp b);
extern void gf_zero(gf_intp a);
extern int gf_iszero(gf_intp a);
extern int gf_isone(gf_intp a);
extern int gf_deg(gf_intp a);

extern void gf_shl(gf_intp a, gf_intp b);
extern void gf_shr(gf_intp a, gf_intp b);
extern void gf_add(gf_intp a, gf_intp b, gf_intp c);
extern void gf_mul(gf_intp a, gf_intp b, gf_intp c);
extern void gf_div(gf_intp a, gf_intp b, gf_intp q, gf_intp r);

extern void gf_mod(gf_intp a, gf_intp m, gf_intp b);
extern void gf_mulmod(gf_intp a, gf_intp b, gf_intp m, gf_intp c);
extern void gf_invmod(gf_intp A, gf_intp M, gf_intp B);
extern void gf_sqrt(gf_intp a, gf_intp M, gf_intp b);
extern void gf_gcd(gf_intp A, gf_intp B, gf_intp c);
extern int gf_is_prime(gf_intp a);

extern int gf_size(gf_intp a);
extern void gf_toraw(gf_intp a, unsigned char *dst);
extern void gf_readraw(gf_intp a, unsigned char *str, int len);

#endif
