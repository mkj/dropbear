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

int hash_file(int hash, const char *fname, unsigned char *dst, unsigned long *outlen)
{
#ifdef NO_FILE
    return CRYPT_NOP;
#else
    FILE *in;
    int err;
    _ARGCHK(fname  != NULL);
    _ARGCHK(dst    != NULL);
    _ARGCHK(outlen != NULL);

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
        return err;
    }

    in = fopen(fname, "rb");
    if (in == NULL) { 
       return CRYPT_FILE_NOTFOUND;
    }

    err = hash_filehandle(hash, in, dst, outlen);
    if (fclose(in) != 0) {
       return CRYPT_ERROR;
    }

    return err;
#endif
}

