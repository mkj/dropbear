#include "mycrypt.h"

#ifdef MPI

#define UPPER_LIMIT    PRIME_SIZE

/* figures out if a number is prime (MR test) */
int is_prime(mp_int *N, int *result)
{
   int err;
   if ((err = mp_prime_is_prime(N, 8, result)) != MP_OKAY) {
      return CRYPT_MEM;
   }
   return CRYPT_OK;
}

int rand_prime(mp_int *N, long len, prng_state *prng, int wprng)
{
   unsigned char buf[260];
   int err, step, ormask;

   _ARGCHK(N != NULL);

   /* pass a negative size if you want a prime congruent to 3 mod 4 */
   if (len < 0) {
      step = 1;
      ormask = 3;
      len = -len;
   } else {
      step = 0;
      ormask = 1;
   }

   /* allow sizes between 2 and 256 bytes for a prime size */
   if (len < 2 || len > 256) { 
      return CRYPT_INVALID_PRIME_SIZE;
   }
   
   /* valid PRNG? */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err; 
   }

   /* read the prng */
   if (prng_descriptor[wprng].read(buf+2, (unsigned long)len, prng) != (unsigned long)len) { 
      return CRYPT_ERROR_READPRNG; 
   }

   /* set sign byte to zero */
   buf[0] = (unsigned char)0;

   /* Set the top byte to 0x01 which makes the number a len*8 bit number */
   buf[1] = (unsigned char)0x01;

   /* set the LSB to the desired settings 
    * (1 for any prime, 3 for primes congruent to 3 mod 4) 
    */
   buf[len+1] |= (unsigned char)ormask;

   /* read the number in */
   if (mp_read_raw(N, buf, 2+len) != MP_OKAY) { 
      return CRYPT_MEM; 
   }

   /* Find the next prime after N */
   if (mp_prime_next_prime(N, 8, step) != MP_OKAY) {
      return CRYPT_MEM;
   }

#ifdef CLEAN_STACK   
   zeromem(buf, sizeof(buf));
#endif

   return CRYPT_OK;
}
      
#endif

