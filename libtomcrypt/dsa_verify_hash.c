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

int dsa_verify_hash(const unsigned char *sig, unsigned long siglen,
                    const unsigned char *hash, unsigned long inlen, 
                    int *stat, dsa_key *key)
{
   mp_int r, s, w, v, u1, u2;
   unsigned long x, y;
   int err;

   _ARGCHK(sig  != NULL);
   _ARGCHK(hash != NULL);
   _ARGCHK(stat != NULL);
   _ARGCHK(key  != NULL);

   /* default to invalid signature */
   *stat = 0;

   if (siglen < PACKET_SIZE+2+2) {
      return CRYPT_INVALID_PACKET;
   } 

   /* is the message format correct? */
   if ((err = packet_valid_header((unsigned char *)sig, PACKET_SECT_DSA, PACKET_SUB_SIGNED)) != CRYPT_OK) {
      return err;
   }

   /* skip over header */
   y = PACKET_SIZE;

   /* init our variables */
   if ((err = mp_init_multi(&r, &s, &w, &v, &u1, &u2, NULL)) != MP_OKAY) {
      return mpi_to_ltc_error(err);
   }

   /* read in r followed by s */
   x = ((unsigned)sig[y]<<8)|((unsigned)sig[y+1]);
   y += 2;
   if (y + x > siglen) { 
      err = CRYPT_INVALID_PACKET;
      goto done;
   }
   if ((err = mp_read_unsigned_bin(&r, (unsigned char *)sig+y, x)) != MP_OKAY)             { goto error; }
   y += x;

   /* load s */
   x = ((unsigned)sig[y]<<8)|((unsigned)sig[y+1]);
   y += 2;
   if (y + x > siglen) { 
      err = CRYPT_INVALID_PACKET;
      goto done;
   }
   if ((err = mp_read_unsigned_bin(&s, (unsigned char *)sig+y, x)) != MP_OKAY)             { goto error; }

   /* w = 1/s mod q */
   if ((err = mp_invmod(&s, &key->q, &w)) != MP_OKAY)                                      { goto error; }

   /* u1 = m * w mod q */
   if ((err = mp_read_unsigned_bin(&u1, (unsigned char *)hash, inlen)) != MP_OKAY)         { goto error; }
   if ((err = mp_mulmod(&u1, &w, &key->q, &u1)) != MP_OKAY)                                { goto error; }

   /* u2 = r*w mod q */
   if ((err = mp_mulmod(&r, &w, &key->q, &u2)) != MP_OKAY)                                 { goto error; } 

   /* v = g^u1 * y^u2 mod p mod q */
   if ((err = mp_exptmod(&key->g, &u1, &key->p, &u1)) != MP_OKAY)                          { goto error; }
   if ((err = mp_exptmod(&key->y, &u2, &key->p, &u2)) != MP_OKAY)                          { goto error; }
   if ((err = mp_mulmod(&u1, &u2, &key->p, &v)) != MP_OKAY)                                { goto error; }
   if ((err = mp_mod(&v, &key->q, &v)) != MP_OKAY)                                         { goto error; }

   /* if r = v then we're set */
   if (mp_cmp(&r, &v) == MP_EQ) {
      *stat = 1;
   }

   err = CRYPT_OK;
   goto done;

error : err = mpi_to_ltc_error(err);
done  : mp_clear_multi(&r, &s, &w, &v, &u1, &u2, NULL);
   return err;
}

#endif

