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

static int next_prime(mp_int *N, mp_digit step)
{
    long x, s, j, total_dist;
    int res;
    mp_int n1, a, y, r;
    mp_digit dist, residues[UPPER_LIMIT];

    _ARGCHK(N != NULL);

    /* first find the residues */
    for (x = 0; x < (long)UPPER_LIMIT; x++) {
        if (mp_mod_d(N, __prime_tab[x], &residues[x]) != MP_OKAY) {
           return CRYPT_MEM;
        }
    }

    /* init variables */
    if (mp_init_multi(&r, &n1, &a, &y, NULL) != MP_OKAY) {
       return CRYPT_MEM;
    }
    
    total_dist = 0;
loop:
    /* while one of the residues is zero keep looping */
    dist = step;
    for (x = 0; (dist < (MP_DIGIT_MAX-step-1)) && (x < (long)UPPER_LIMIT); x++) {
        j = (long)residues[x] + (long)dist + total_dist;
        if (j % (long)__prime_tab[x] == 0) {
           dist += step; x = -1;
        }
    }
    
    /* recalc the total distance from where we started */
    total_dist += dist;
    
    /* add to N */
    if (mp_add_d(N, dist, N) != MP_OKAY) { goto error; }
    
    /* n1 = N - 1 */
    if (mp_sub_d(N, 1, &n1) != MP_OKAY)  { goto error; }

    /* r = N - 1 */
    if (mp_copy(&n1, &r) != MP_OKAY)     { goto error; }

    /* find s such that N-1 = (2^s)r */
    s = 0;
    while (mp_iseven(&r)) {
        ++s;
        if (mp_div_2(&r, &r) != MP_OKAY) {
           goto error;
        }
    }
    for (x = 0; x < 8; x++) {
        /* choose a */
        mp_set(&a, __prime_tab[x]);

        /* compute y = a^r mod n */
        if (mp_exptmod(&a, &r, N, &y) != MP_OKAY)             { goto error; }

        /* (y != 1) AND (y != N-1) */
        if ((mp_cmp_d(&y, 1) != 0) && (mp_cmp(&y, &n1) != 0)) {
            /* while j <= s-1 and y != n-1 */
            for (j = 1; (j <= (s-1)) && (mp_cmp(&y, &n1) != 0); j++) {
                /* y = y^2 mod N */
                if (mp_sqrmod(&y, N, &y) != MP_OKAY)          { goto error; }

                /* if y == 1 return false */
                if (mp_cmp_d(&y, 1) == 0)                     { goto loop; }
            }

            /* if y != n-1 return false */
            if (mp_cmp(&y, &n1) != 0)                         { goto loop; }
        }
    }

    res = CRYPT_OK;
    goto done;
error:
    res = CRYPT_MEM;
done:
    mp_clear_multi(&a, &y, &n1, &r, NULL);

#ifdef CLEAN_STACK
    zeromem(residues, sizeof(residues));
#endif    
    return res;
}

int rand_prime(mp_int *N, long len, prng_state *prng, int wprng)
{
   unsigned char buf[260];
   int err, step, ormask;

   _ARGCHK(N != NULL);

   /* pass a negative size if you want a prime congruent to 3 mod 4 */
   if (len < 0) {
      step = 4;
      ormask = 3;
      len = -len;
   } else {
      step = 2;
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

   /* add the step size to it while N is not prime */
   if ((err = next_prime(N, step)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK   
   zeromem(buf, sizeof(buf));
#endif

   return CRYPT_OK;
}
      
#endif

