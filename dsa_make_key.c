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

#ifdef MDSA

int dsa_make_key(prng_state *prng, int wprng, int group_size, int modulus_size, dsa_key *key)
{
   mp_int         tmp, tmp2;
   int            err, res;
   unsigned char *buf;

   _ARGCHK(key  != NULL);

   /* check prng */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* check size */
   if (group_size >= MDSA_MAX_GROUP || group_size <= 15 || 
       group_size >= modulus_size || (modulus_size - group_size) >= MDSA_DELTA) {
      return CRYPT_INVALID_ARG;
   }

   /* allocate ram */
   buf = XMALLOC(MDSA_DELTA);
   if (buf == NULL) {
      return CRYPT_MEM;
   }

   /* init mp_ints  */
   if ((err = mp_init_multi(&tmp, &tmp2, &key->g, &key->q, &key->p, &key->x, &key->y, NULL)) != MP_OKAY) {
      err = mpi_to_ltc_error(err);
      goto __ERR;
   }

   /* make our prime q */
   if ((err = rand_prime(&key->q, group_size*8, prng, wprng)) != CRYPT_OK)             { goto __ERR; }

   /* double q  */
   if ((err = mp_mul_2(&key->q, &tmp)) != MP_OKAY)                                     { goto error; }

   /* now make a random string and multply it against q */
   if (prng_descriptor[wprng].read(buf+1, modulus_size - group_size, prng) != (unsigned long)(modulus_size - group_size)) {
      err = CRYPT_ERROR_READPRNG;
      goto __ERR;
   }

   /* force magnitude */
   buf[0] = 1;

   /* force even */
   buf[modulus_size - group_size] &= ~1;

   if ((err = mp_read_unsigned_bin(&tmp2, buf, modulus_size - group_size+1)) != MP_OKAY) { goto error; }
   if ((err = mp_mul(&key->q, &tmp2, &key->p)) != MP_OKAY)                             { goto error; }
   if ((err = mp_add_d(&key->p, 1, &key->p)) != MP_OKAY)                               { goto error; }
   
   /* now loop until p is prime */
   for (;;) {
       if ((err = is_prime(&key->p, &res)) != CRYPT_OK)                                { goto __ERR; }
       if (res == MP_YES) break;

       /* add 2q to p and 2 to tmp2 */
       if ((err = mp_add(&tmp, &key->p, &key->p)) != MP_OKAY)                          { goto error; }
       if ((err = mp_add_d(&tmp2, 2, &tmp2)) != MP_OKAY)                               { goto error; }
   }

   /* now p = (q * tmp2) + 1 is prime, find a value g for which g^tmp2 != 1 */
   mp_set(&key->g, 1);

   do {
      if ((err = mp_add_d(&key->g, 1, &key->g)) != MP_OKAY)                            { goto error; }
      if ((err = mp_exptmod(&key->g, &tmp2, &key->p, &tmp)) != MP_OKAY)                { goto error; }
   } while (mp_cmp_d(&tmp, 1) == MP_EQ);

   /* at this point tmp generates a group of order q mod p */
   mp_exch(&tmp, &key->g);

   /* so now we have our DH structure, generator g, order q, modulus p 
      Now we need a random exponent [mod q] and it's power g^x mod p 
    */
   do {
      if (prng_descriptor[wprng].read(buf, group_size, prng) != (unsigned long)group_size) {
         err = CRYPT_ERROR_READPRNG;
         goto __ERR;
      }
      if ((err = mp_read_unsigned_bin(&key->x, buf, group_size)) != MP_OKAY)           { goto error; }
   } while (mp_cmp_d(&key->x, 1) != MP_GT);
   if ((err = mp_exptmod(&key->g, &key->x, &key->p, &key->y)) != MP_OKAY)              { goto error; }
   
   key->type = PK_PRIVATE;
   key->qord = group_size;

   /* shrink the ram required */
   if ((err = mp_shrink(&key->g)) != MP_OKAY)                                          { goto error; }
   if ((err = mp_shrink(&key->p)) != MP_OKAY)                                          { goto error; }
   if ((err = mp_shrink(&key->q)) != MP_OKAY)                                          { goto error; }
   if ((err = mp_shrink(&key->x)) != MP_OKAY)                                          { goto error; }
   if ((err = mp_shrink(&key->y)) != MP_OKAY)                                          { goto error; }

#ifdef CLEAN_STACK
   zeromem(buf, MDSA_DELTA);
#endif

   err = CRYPT_OK;
   goto done;
error: 
    err = mpi_to_ltc_error(err);
__ERR: 
    mp_clear_multi(&key->g, &key->q, &key->p, &key->x, &key->y, NULL);
done: 
    mp_clear_multi(&tmp, &tmp2, NULL);

    XFREE(buf);
    return err;
}

#endif
