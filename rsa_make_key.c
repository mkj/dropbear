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

#ifdef MRSA

int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key)
{
   mp_int p, q, tmp1, tmp2, tmp3;
   int    err;

   _ARGCHK(key != NULL);

   if ((size < (MIN_RSA_SIZE/8)) || (size > (MAX_RSA_SIZE/8))) {
      return CRYPT_INVALID_KEYSIZE;
   }

   if ((e < 3) || ((e & 1) == 0)) {
      return CRYPT_INVALID_ARG;
   }

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   if ((err = mp_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* make primes p and q (optimization provided by Wayne Scott) */
   if ((err = mp_set_int(&tmp3, e)) != MP_OKAY) { goto error; }            /* tmp3 = e */

   /* make prime "p" */
   do {
       if ((err = rand_prime(&p, size*4, prng, wprng)) != CRYPT_OK) { goto done; }
       if ((err = mp_sub_d(&p, 1, &tmp1)) != MP_OKAY)               { goto error; }  /* tmp1 = p-1 */
       if ((err = mp_gcd(&tmp1, &tmp3, &tmp2)) != MP_OKAY)          { goto error; }  /* tmp2 = gcd(p-1, e) */
   } while (mp_cmp_d(&tmp2, 1) != 0);                                                /* while e divides p-1 */

   /* make prime "q" */
   do {
       if ((err = rand_prime(&q, size*4, prng, wprng)) != CRYPT_OK) { goto done; }
       if ((err = mp_sub_d(&q, 1, &tmp1)) != MP_OKAY)               { goto error; } /* tmp1 = q-1 */
       if ((err = mp_gcd(&tmp1, &tmp3, &tmp2)) != MP_OKAY)          { goto error; } /* tmp2 = gcd(q-1, e) */
   } while (mp_cmp_d(&tmp2, 1) != 0);                                               /* while e divides q-1 */

   /* tmp1 = lcm(p-1, q-1) */
   if ((err = mp_sub_d(&p, 1, &tmp2)) != MP_OKAY)                  { goto error; } /* tmp2 = p-1 */
                                                                   /* tmp1 = q-1 (previous do/while loop) */
   if ((err = mp_lcm(&tmp1, &tmp2, &tmp1)) != MP_OKAY)             { goto error; } /* tmp1 = lcm(p-1, q-1) */

   /* make key */
   if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP,
                     &key->qP, &key->pQ, &key->p, &key->q, NULL)) != MP_OKAY) {
      goto error;
   }

   if ((err = mp_set_int(&key->e, e)) != MP_OKAY)                  { goto error2; } /* key->e =  e */
   if ((err = mp_invmod(&key->e, &tmp1, &key->d)) != MP_OKAY)      { goto error2; } /* key->d = 1/e mod lcm(p-1,q-1) */
   if ((err = mp_mul(&p, &q, &key->N)) != MP_OKAY)                 { goto error2; } /* key->N = pq */

/* optimize for CRT now */
   /* find d mod q-1 and d mod p-1 */
   if ((err = mp_sub_d(&p, 1, &tmp1)) != MP_OKAY)                  { goto error2; } /* tmp1 = q-1 */
   if ((err = mp_sub_d(&q, 1, &tmp2)) != MP_OKAY)                  { goto error2; } /* tmp2 = p-1 */

   if ((err = mp_mod(&key->d, &tmp1, &key->dP)) != MP_OKAY)        { goto error2; } /* dP = d mod p-1 */
   if ((err = mp_mod(&key->d, &tmp2, &key->dQ)) != MP_OKAY)        { goto error2; } /* dQ = d mod q-1 */

   if ((err = mp_invmod(&q, &p, &key->qP)) != MP_OKAY)             { goto error2; } /* qP = 1/q mod p */
   if ((err = mp_mulmod(&key->qP, &q, &key->N, &key->qP)) != MP_OKAY)         { goto error2; } /* qP = q * (1/q mod p) mod N */

   if ((err = mp_invmod(&p, &q, &key->pQ)) != MP_OKAY)             { goto error2; } /* pQ = 1/p mod q */
   if ((err = mp_mulmod(&key->pQ, &p, &key->N, &key->pQ)) != MP_OKAY)         { goto error2; } /* pQ = p * (1/p mod q) mod N */

   if ((err = mp_copy(&p, &key->p)) != MP_OKAY)                    { goto error2; }
   if ((err = mp_copy(&q, &key->q)) != MP_OKAY)                    { goto error2; }

   /* shrink ram required  */
   if ((err = mp_shrink(&key->e)) != MP_OKAY)                      { goto error2; }
   if ((err = mp_shrink(&key->d)) != MP_OKAY)                      { goto error2; }
   if ((err = mp_shrink(&key->N)) != MP_OKAY)                      { goto error2; }
   if ((err = mp_shrink(&key->dQ)) != MP_OKAY)                     { goto error2; }
   if ((err = mp_shrink(&key->dP)) != MP_OKAY)                     { goto error2; }
   if ((err = mp_shrink(&key->qP)) != MP_OKAY)                     { goto error2; }
   if ((err = mp_shrink(&key->pQ)) != MP_OKAY)                     { goto error2; }
   if ((err = mp_shrink(&key->p)) != MP_OKAY)                      { goto error2; }
   if ((err = mp_shrink(&key->q)) != MP_OKAY)                      { goto error2; }

   err = CRYPT_OK;
   key->type = PK_PRIVATE_OPTIMIZED;
   goto done;
error2:
   mp_clear_multi(&key->d, &key->e, &key->N, &key->dQ, &key->dP,
                  &key->qP, &key->pQ, &key->p, &key->q, NULL);
error:
   err = mpi_to_ltc_error(err);
done:
   mp_clear_multi(&tmp3, &tmp2, &tmp1, &p, &q, NULL);
   return err;
}

#endif
