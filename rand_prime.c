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
#include "mycrypt.h"

#ifdef MPI

struct rng_data {
   prng_state *prng;
   int         wprng;
};

static int rand_prime_helper(unsigned char *dst, int len, void *dat)
{
   return (int)prng_descriptor[((struct rng_data *)dat)->wprng].read(dst, len, ((struct rng_data *)dat)->prng);
}

int rand_prime(mp_int *N, long len, prng_state *prng, int wprng)
{
   struct rng_data rng;
   int             type, err;

   _ARGCHK(N != NULL);

   /* allow sizes between 2 and 256 bytes for a prime size */
   if (len < 16 || len > 4096) { 
      return CRYPT_INVALID_PRIME_SIZE;
   }
   
   /* valid PRNG? Better be! */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err; 
   }

   /* setup our callback data, then world domination! */
   rng.prng  = prng;
   rng.wprng = wprng;

   /* get type */
   if (len < 0) {
      type = LTM_PRIME_BBS;
      len = -len;
   } else {
      type = 0;
   }

   /* New prime generation makes the code even more cryptoish-insane.  Do you know what this means!!!
      -- Gir:  Yeah, oh wait, er, no.
    */
   if ((err = mp_prime_random_ex(N, mp_prime_rabin_miller_trials(len), len, type, rand_prime_helper, &rng)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   return CRYPT_OK;
}
      
#endif

