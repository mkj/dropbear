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

int dsa_import(const unsigned char *in, unsigned long inlen, dsa_key *key)
{
   unsigned long x, y;
   int err;

   _ARGCHK(in  != NULL);
   _ARGCHK(key != NULL);

   /* check length */
   if ((1+2+PACKET_SIZE) > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   /* check type */
   if ((err = packet_valid_header((unsigned char *)in, PACKET_SECT_DSA, PACKET_SUB_KEY)) != CRYPT_OK) {
      return err;
   }
   y = PACKET_SIZE;

   /* init key */
   if (mp_init_multi(&key->p, &key->g, &key->q, &key->x, &key->y, NULL) != MP_OKAY) {
      return CRYPT_MEM;
   }

   /* read type/qord */
   key->type = in[y++];
   key->qord = ((unsigned)in[y]<<8)|((unsigned)in[y+1]);
   y += 2;

   /* input publics */
   INPUT_BIGNUM(&key->g,in,x,y, inlen);
   INPUT_BIGNUM(&key->p,in,x,y, inlen);
   INPUT_BIGNUM(&key->q,in,x,y, inlen);
   INPUT_BIGNUM(&key->y,in,x,y, inlen);
   if (key->type == PK_PRIVATE) {
      INPUT_BIGNUM(&key->x,in,x,y, inlen);
   }

   return CRYPT_OK;
error: 
   mp_clear_multi(&key->p, &key->g, &key->q, &key->x, &key->y, NULL);
   return err;
}

#endif
