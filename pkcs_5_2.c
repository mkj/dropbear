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
#include <mycrypt.h>

/* PKCS #5, Algorithm #2 */
#ifdef PKCS_5

int pkcs_5_alg2(const unsigned char *password, unsigned long password_len, 
                const unsigned char *salt,     unsigned long salt_len,
                int iteration_count,           int hash_idx,
                unsigned char *out,            unsigned long *outlen)
{
   int err, itts;
   unsigned long stored, left, x, y, blkno;
   unsigned char *buf[2];
   hmac_state    *hmac;

   _ARGCHK(password != NULL);
   _ARGCHK(salt     != NULL);
   _ARGCHK(out      != NULL);
   _ARGCHK(outlen   != NULL);

   /* test hash IDX */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }

   buf[0] = XMALLOC(MAXBLOCKSIZE * 2);
   hmac   = XMALLOC(sizeof(hmac_state));
   if (hmac == NULL || buf[0] == NULL) {
      if (hmac != NULL) {
         XFREE(hmac);
      }
      if (buf[0] != NULL) {
         XFREE(buf[0]);
      }
      return CRYPT_MEM;
   }
   /* buf[1] points to the second block of MAXBLOCKSIZE bytes */
   buf[1] = buf[0] + MAXBLOCKSIZE;

   left   = *outlen;
   blkno  = 1;
   stored = 0;
   while (left != 0) {
       /* process block number blkno */
       zeromem(buf[0], MAXBLOCKSIZE*2);
       
       /* store current block number and increment for next pass */
       STORE32H(blkno, buf[1]);
       ++blkno;

       /* get PRF(P, S||int(blkno)) */
       if ((err = hmac_init(hmac, hash_idx, password, password_len)) != CRYPT_OK) { 
          goto __ERR;
       }
       if ((err = hmac_process(hmac, salt, salt_len)) != CRYPT_OK) {
          goto __ERR;
       }
       if ((err = hmac_process(hmac, buf[1], 4)) != CRYPT_OK) {
          goto __ERR;
       }
       x = MAXBLOCKSIZE;
       if ((err = hmac_done(hmac, buf[0], &x)) != CRYPT_OK) {
          goto __ERR;
       }

       /* now compute repeated and XOR it in buf[1] */
       XMEMCPY(buf[1], buf[0], x);
       for (itts = 1; itts < iteration_count; ++itts) {
           if ((err = hmac_memory(hash_idx, password, password_len, buf[0], x, buf[0], &x)) != CRYPT_OK) {
              goto __ERR;
           }
           for (y = 0; y < x; y++) {
               buf[1][y] ^= buf[0][y];
           }
       }

       /* now emit upto x bytes of buf[1] to output */
       for (y = 0; y < x && left != 0; ++y) {
           out[stored++] = buf[1][y];
           --left;
       }
   }
   *outlen = stored;

   err = CRYPT_OK;
__ERR:
#ifdef CLEAN_STACK
   zeromem(buf[0], MAXBLOCKSIZE*2);
   zeromem(hmac, sizeof(hmac_state));
#endif

   XFREE(hmac);
   XFREE(buf[0]);

   return err;
}

#endif

