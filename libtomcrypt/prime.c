#include "mycrypt.h"

#ifdef MPI

#define UPPER_LIMIT    (sizeof(prime_tab) / sizeof(prime_tab[0]))

static const mp_digit prime_tab[] = {
    0x0002, 0x0003, 0x0005, 0x0007, 0x000B, 0x000D, 0x0011, 0x0013,
    0x0017, 0x001D, 0x001F, 0x0025, 0x0029, 0x002B, 0x002F, 0x0035,
    0x003B, 0x003D, 0x0043, 0x0047, 0x0049, 0x004F, 0x0053, 0x0059,
    0x0061, 0x0065, 0x0067, 0x006B, 0x006D, 0x0071, 0x007F, 0x0083,
    0x0089, 0x008B, 0x0095, 0x0097, 0x009D, 0x00A3, 0x00A7, 0x00AD,
    0x00B3, 0x00B5, 0x00BF, 0x00C1, 0x00C5, 0x00C7, 0x00D3, 0x00DF,
    0x00E3, 0x00E5, 0x00E9, 0x00EF, 0x00F1, 0x00FB, 0x0101, 0x0107,
    0x010D, 0x010F, 0x0115, 0x0119, 0x011B, 0x0125, 0x0133, 0x0137,
    
    0x0139, 0x013D, 0x014B, 0x0151, 0x015B, 0x015D, 0x0161, 0x0167, 
    0x016F, 0x0175, 0x017B, 0x017F, 0x0185, 0x018D, 0x0191, 0x0199, 
    0x01A3, 0x01A5, 0x01AF, 0x01B1, 0x01B7, 0x01BB, 0x01C1, 0x01C9, 
    0x01CD, 0x01CF, 0x01D3, 0x01DF, 0x01E7, 0x01EB, 0x01F3, 0x01F7, 
    0x01FD, 0x0209, 0x020B, 0x021D, 0x0223, 0x022D, 0x0233, 0x0239, 
    0x023B, 0x0241, 0x024B, 0x0251, 0x0257, 0x0259, 0x025F, 0x0265, 
    0x0269, 0x026B, 0x0277, 0x0281, 0x0283, 0x0287, 0x028D, 0x0293, 
    0x0295, 0x02A1, 0x02A5, 0x02AB, 0x02B3, 0x02BD, 0x02C5, 0x02CF, 

    0x02D7, 0x02DD, 0x02E3, 0x02E7, 0x02EF, 0x02F5, 0x02F9, 0x0301, 
    0x0305, 0x0313, 0x031D, 0x0329, 0x032B, 0x0335, 0x0337, 0x033B, 
    0x033D, 0x0347, 0x0355, 0x0359, 0x035B, 0x035F, 0x036D, 0x0371, 
    0x0373, 0x0377, 0x038B, 0x038F, 0x0397, 0x03A1, 0x03A9, 0x03AD, 
    0x03B3, 0x03B9, 0x03C7, 0x03CB, 0x03D1, 0x03D7, 0x03DF, 0x03E5,
    0x03F1, 0x03F5, 0x03FB, 0x03FD, 0x0407, 0x0409, 0x040F, 0x0419, 
    0x041B, 0x0425, 0x0427, 0x042D, 0x043F, 0x0443, 0x0445, 0x0449, 
    0x044F, 0x0455, 0x045D, 0x0463, 0x0469, 0x047F, 0x0481, 0x048B,
    
    0x0493, 0x049D, 0x04A3, 0x04A9, 0x04B1, 0x04BD, 0x04C1, 0x04C7, 
    0x04CD, 0x04CF, 0x04D5, 0x04E1, 0x04EB, 0x04FD, 0x04FF, 0x0503, 
    0x0509, 0x050B, 0x0511, 0x0515, 0x0517, 0x051B, 0x0527, 0x0529, 
    0x052F, 0x0551, 0x0557, 0x055D, 0x0565, 0x0577, 0x0581, 0x058F, 
    0x0593, 0x0595, 0x0599, 0x059F, 0x05A7, 0x05AB, 0x05AD, 0x05B3, 
    0x05BF, 0x05C9, 0x05CB, 0x05CF, 0x05D1, 0x05D5, 0x05DB, 0x05E7, 
    0x05F3, 0x05FB, 0x0607, 0x060D, 0x0611, 0x0617, 0x061F, 0x0623, 
    0x062B, 0x062F, 0x063D, 0x0641, 0x0647, 0x0649, 0x064D, 0x0653 };    


/* figures out if a number is prime (MR test) */
#ifdef CLEAN_STACK
static int _is_prime(mp_int *N, int *result)
#else
int is_prime(mp_int *N, int *result)
#endif
{
    long x, s, j;
    int res;
    mp_int n1, a, y, r;
    mp_digit d;
    
    _ARGCHK(N != NULL);
    _ARGCHK(result != NULL);

    /* default to answer of no */
    *result = 0;

    /* divisible by any of the first primes? */
    for (x = 0; x < (long)UPPER_LIMIT; x++) {
        /* is N equal to a small prime? */
        if (mp_cmp_d(N, prime_tab[x]) == 0) { 
            *result = 1; 
             return CRYPT_OK; 
        }

        /* is N mod prime_tab[x] == 0, then its divisible by it */
        if (mp_mod_d(N, prime_tab[x], &d) != MP_OKAY) {
           return CRYPT_MEM;
        }

        if (d == 0) {
           return CRYPT_OK;
        }
    }

    /* init variables */
    if (mp_init_multi(&r, &n1, &a, &y, NULL) != MP_OKAY) {
       return CRYPT_MEM;
    }

    /* n1 = N - 1 */
    if (mp_sub_d(N, 1, &n1) != MP_OKAY) { goto error; }

    /* r = N - 1 */
    if (mp_copy(&n1, &r) != MP_OKAY)    { goto error; }

    /* find s such that N-1 = (2^s)r */
    s = 0;
    while (mp_iseven(&r) != 0) {
        ++s;
        if (mp_div_2(&r, &r) != MP_OKAY) {
           goto error;
        }
    }

    for (x = 0; x < 8; x++) {
        /* choose a */
        mp_set(&a, prime_tab[x]);

        /* compute y = a^r mod n */
        if (mp_exptmod(&a, &r, N, &y) != MP_OKAY)             { goto error; }

        /* (y != 1) AND (y != N-1) */
        if ((mp_cmp_d(&y, 1) != 0) && (mp_cmp(&y, &n1) != 0)) {
            /* while j <= s-1 and y != n-1 */
            for (j = 1; (j <= (s-1)) && (mp_cmp(&y, &n1) != 0); j++) {
                /* y = y^2 mod N */
                if (mp_sqrmod(&y, N, &y) != MP_OKAY)          { goto error; }

                /* if y == 1 return false */
                if (mp_cmp_d(&y, 1) == 0)                     { goto ok; }
            }

            /* if y != n-1 return false */
            if (mp_cmp(&y, &n1) != 0)                         { goto ok; }
        }
    }
    *result = 1;
ok:
    res = CRYPT_OK;
    goto done;
error:
    res = CRYPT_MEM;
done:
    mp_clear_multi(&a, &y, &n1, &r, NULL);
    return res;
}

#ifdef CLEAN_STACK
int is_prime(mp_int *N, int *result)
{
   int x;
   x = _is_prime(N, result);
   burn_stack(sizeof(long) * 3 + sizeof(int) + sizeof(mp_int) * 4 + sizeof(mp_digit));
   return x;
}
#endif

static int next_prime(mp_int *N, mp_digit step)
{
    long x, s, j, total_dist;
    int res;
    mp_int n1, a, y, r;
    mp_digit dist, residues[UPPER_LIMIT];

    _ARGCHK(N != NULL);

    /* first find the residues */
    for (x = 0; x < (long)UPPER_LIMIT; x++) {
        if (mp_mod_d(N, prime_tab[x], &residues[x]) != MP_OKAY) {
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
        if (j % (long)prime_tab[x] == 0) {
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
        mp_set(&a, prime_tab[x]);

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

