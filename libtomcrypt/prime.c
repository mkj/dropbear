#include "mycrypt.h"

#ifdef MPI

struct rng_data {
   prng_state *prng;
   int         wprng;
};


#define UPPER_LIMIT    PRIME_SIZE

/* figures out if a number is prime (MR test) */
int is_prime(mp_int *N, int *result)
{
   int err;
   _ARGCHK(N != NULL);
   _ARGCHK(result != NULL);
   if ((err = mp_prime_is_prime(N, mp_prime_rabin_miller_trials(mp_count_bits(N)), result)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }
   return CRYPT_OK;
}

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
   if (len < 2 || len > 256) { 
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
      type = 1;
      len = -len;
   } else {
      type = 0;
   }

   /* New prime generation makes the code even more cryptoish-insane.  Do you know what this means!!!
      -- Gir:  Yeah, oh wait, er, no.
    */
   if ((err = mp_prime_random(N, mp_prime_rabin_miller_trials(len*8), len, type, rand_prime_helper, &rng)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   return CRYPT_OK;
}
      
#endif

