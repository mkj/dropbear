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

int hash_memory(int hash, const unsigned char *data, unsigned long len, unsigned char *dst, unsigned long *outlen)
{
    hash_state *md;
    int err;

    _ARGCHK(data   != NULL);
    _ARGCHK(dst    != NULL);
    _ARGCHK(outlen != NULL);

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
        return err;
    }

    if (*outlen < hash_descriptor[hash].hashsize) {
       return CRYPT_BUFFER_OVERFLOW;
    }

    md = XMALLOC(sizeof(hash_state));
    if (md == NULL) {
       return CRYPT_MEM;
    }

    if ((err = hash_descriptor[hash].init(md)) != CRYPT_OK) {
       goto __ERR;
    }
    if ((err = hash_descriptor[hash].process(md, data, len)) != CRYPT_OK) {
       goto __ERR;
    }
    err = hash_descriptor[hash].done(md, dst);
    *outlen = hash_descriptor[hash].hashsize;
__ERR:
#ifdef CLEAN_STACK
    zeromem(md, sizeof(hash_state));
#endif
    XFREE(md);

    return err;
}
