#include "mycrypt.h"

int hash_memory(int hash, const unsigned char *data, unsigned long len, unsigned char *dst, unsigned long *outlen)
{
    hash_state md;
    int err;

    _ARGCHK(data != NULL);
    _ARGCHK(dst != NULL);
    _ARGCHK(outlen != NULL);

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
        return err;
    }

    if (*outlen < hash_descriptor[hash].hashsize) {
       return CRYPT_BUFFER_OVERFLOW;
    }
    *outlen = hash_descriptor[hash].hashsize;

    hash_descriptor[hash].init(&md);
    hash_descriptor[hash].process(&md, data, len);
    hash_descriptor[hash].done(&md, dst);
    return CRYPT_OK;
}

int hash_filehandle(int hash, FILE *in, unsigned char *dst, unsigned long *outlen)
{
#ifdef NO_FILE
    return CRYPT_NOP;
#else
    hash_state md;
    unsigned char buf[512];
    size_t x;
    int err;

    _ARGCHK(dst != NULL);
    _ARGCHK(outlen != NULL);
    _ARGCHK(in != NULL);

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
        return err;
    }

    if (*outlen < hash_descriptor[hash].hashsize) {
       return CRYPT_BUFFER_OVERFLOW;
    }
    *outlen = hash_descriptor[hash].hashsize;

    hash_descriptor[hash].init(&md);
    do {
        x = fread(buf, 1, sizeof(buf), in);
        hash_descriptor[hash].process(&md, buf, x);
    } while (x == sizeof(buf));
    hash_descriptor[hash].done(&md, dst);

#ifdef CLEAN_STACK
    zeromem(buf, sizeof(buf));
#endif
    return CRYPT_OK;
#endif
}

int hash_file(int hash, const char *fname, unsigned char *dst, unsigned long *outlen)
{
#ifdef NO_FILE
    return CRYPT_NOP;
#else
    FILE *in;
    int err;
    _ARGCHK(fname != NULL);
    _ARGCHK(dst != NULL);
    _ARGCHK(outlen != NULL);

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
        return err;
    }

    in = fopen(fname, "rb");
    if (in == NULL) { 
       return CRYPT_INVALID_ARG;
    }

    if ((err = hash_filehandle(hash, in, dst, outlen)) != CRYPT_OK) {
       (void)fclose(in);
       return err;
    }
    (void)fclose(in);

    return CRYPT_OK;
#endif
}

