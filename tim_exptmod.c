/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@iahu.ca, http://libtomcrypt.org
 */

/* RSA Code by Tom St Denis */
#include "mycrypt.h"

#ifdef RSA_TIMING

/* decrypts c into m */
int tim_exptmod(prng_state *prng, int prng_idx, 
                mp_int *c, mp_int *e, mp_int *d, mp_int *n, mp_int *m)
{
   int           err;
   mp_int        r, tmp, tmp2;
   unsigned char *rtmp;
   unsigned long rlen;

   _ARGCHK(c != NULL);
   _ARGCHK(e != NULL);
   _ARGCHK(d != NULL);
   _ARGCHK(n != NULL);
   _ARGCHK(m != NULL);

   if ((err = prng_is_valid(prng_idx)) != CRYPT_OK) {
      return err;
   }

   /* pick random r */ 
   rtmp = XMALLOC(MAX_RSA_SIZE/8);
   if (rtmp == NULL) {
      return CRYPT_MEM;
   }


   rlen = mp_unsigned_bin_size(n);
   if (prng_descriptor[prng_idx].read(rtmp, rlen, prng) != rlen) {
      XFREE(rtmp);
      return CRYPT_ERROR_READPRNG;
   }

   if ((err = mp_init_multi(&r, &tmp, &tmp2, NULL)) != MP_OKAY) {
      XFREE(rtmp);
      return mpi_to_ltc_error(err);
   }

   /* read in r */
   if ((err = mp_read_unsigned_bin(&r, rtmp, rlen)) != MP_OKAY)              { goto __ERR; }

   /* compute tmp = r^e */
   if ((err = mp_exptmod(&r, e, n, &tmp)) != MP_OKAY)                        { goto __ERR; }

   /* multiply C into the mix */
   if ((err = mp_mulmod(c, &tmp, n, &tmp)) != MP_OKAY)                       { goto __ERR; }

   /* raise to d */
   if ((err = mp_exptmod(&tmp, d, n, &tmp)) != MP_OKAY)                      { goto __ERR; }
   
   /* invert r and multiply */
   if ((err = mp_invmod(&r, n, &tmp2)) != MP_OKAY)                           { goto __ERR; }

   /* multiply and we are totally set */
   if ((err = mp_mulmod(&tmp, &tmp2, n, m)) != MP_OKAY)                      { goto __ERR; }

__ERR:  mp_clear_multi(&r, &tmp, &tmp2, NULL);
   XFREE(rtmp);
   return mpi_to_ltc_error(err);
}

#endif 
