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
/* Submited by Dobes Vandermeer  (dobes@smartt.com) */

#include "mycrypt.h"

#ifdef HMAC

int hmac_memory(int hash, const unsigned char *key, unsigned long keylen,
                const unsigned char *data, unsigned long len, 
                unsigned char *dst, unsigned long *dstlen)
{
    hmac_state *hmac;
    int err;

    _ARGCHK(key    != NULL);
    _ARGCHK(data   != NULL);
    _ARGCHK(dst    != NULL); 
    _ARGCHK(dstlen != NULL);

    /* allocate ram for hmac state */
    hmac = XMALLOC(sizeof(hmac_state));
    if (hmac == NULL) {
       return CRYPT_MEM;
    }

    if ((err = hmac_init(hmac, hash, key, keylen)) != CRYPT_OK) {
       goto __ERR;
    }

    if ((err = hmac_process(hmac, data, len)) != CRYPT_OK) {
       goto __ERR;
    }

    if ((err = hmac_done(hmac, dst, dstlen)) != CRYPT_OK) {
       goto __ERR;
    }

   err = CRYPT_OK;
__ERR:
#ifdef CLEAN_STACK
   zeromem(hmac, sizeof(hmac_state));
#endif

   XFREE(hmac);
   return err;   
}

#endif

