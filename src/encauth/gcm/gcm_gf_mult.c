/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */

/**
   @file gcm_gf_mult.c
   GCM implementation, initialize state, by Tom St Denis
*/
#include "tomcrypt.h"

#ifdef GCM_MODE

/* right shift */
static void gcm_rightshift(unsigned char *a)
{
   int x;
   for (x = 15; x > 0; x--) {
       a[x] = (a[x]>>1) | ((a[x-1]<<7)&0x80);
   }
   a[0] >>= 1;
}

/* c = b*a */
static const unsigned char mask[] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
static const unsigned char poly[] = { 0x00, 0xE1 };

/**
  GCM GF multiplier (internal use only) 
  @param a   First value
  @param b   Second value
  @param c   Destination for a * b
 */  
void gcm_gf_mult(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
   unsigned char Z[16], V[16];
   unsigned x, y, z;

   zeromem(Z, 16);
   XMEMCPY(V, a, 16);
   for (x = 0; x < 128; x++) {
       if (b[x>>3] & mask[x&7]) {
          for (y = 0; y < 16; y++) {
              Z[y] ^= V[y]; 
          }
       }
       z     = V[15] & 0x01;
       gcm_rightshift(V);
       V[0] ^= poly[z];
   }
   XMEMCPY(c, Z, 16);
}

/**
  GCM multiply by H
  @param gcm   The GCM state which holds the H value
  @param I     The value to multiply H by
 */
void gcm_mult_h(gcm_state *gcm, unsigned char *I)
{
   unsigned char T[16];
#ifdef GCM_TABLES
   int x, y;
   XMEMCPY(T, &gcm->PC[0][I[0]][0], 16);
   for (x = 1; x < 16; x++) {
#ifdef LTC_FAST
       for (y = 0; y < 16; y += sizeof(LTC_FAST_TYPE)) {
           *((LTC_FAST_TYPE *)(T + y)) ^= *((LTC_FAST_TYPE *)(&gcm->PC[x][I[x]][y]));
       }
#else
       for (y = 0; y < 16; y++) {
           T[y] ^= gcm->PC[x][I[x]][y];
       }
#endif
   }
#else     
   gcm_gf_mult(gcm->H, I, T); 
#endif
   XMEMCPY(I, T, 16);
}


#endif
