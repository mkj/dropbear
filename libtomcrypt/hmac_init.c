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

/*
    (1) append zeros to the end of K to create a B byte string
        (e.g., if K is of length 20 bytes and B=64, then K will be
         appended with 44 zero bytes 0x00)
    (2) XOR (bitwise exclusive-OR) the B byte string computed in step
        (1) with ipad (ipad = the byte 0x36 repeated B times)
    (3) append the stream of data 'text' to the B byte string resulting
        from step (2)
    (4) apply H to the stream generated in step (3)
    (5) XOR (bitwise exclusive-OR) the B byte string computed in
        step (1) with opad (opad = the byte 0x5C repeated B times.)
    (6) append the H result from step (4) to the B byte string
        resulting from step (5)
    (7) apply H to the stream generated in step (6) and output
        the result
*/

#ifdef HMAC

#define HMAC_BLOCKSIZE hash_descriptor[hash].blocksize

int hmac_init(hmac_state *hmac, int hash, const unsigned char *key, unsigned long keylen)
{
    unsigned char buf[MAXBLOCKSIZE];
    unsigned long hashsize;
    unsigned long i, z;
    int err;

    _ARGCHK(hmac != NULL);
    _ARGCHK(key != NULL);

    if ((err = hash_is_valid(hash)) != CRYPT_OK) {
        return err;
    }

    /* valid key length? */
    if (keylen == 0) {
        return CRYPT_INVALID_KEYSIZE;
    }

    hmac->hash = hash;

    // (1) make sure we have a large enough key
    hashsize = hash_descriptor[hash].hashsize;
    if(keylen > HMAC_BLOCKSIZE) {
        z = (unsigned long)sizeof(hmac->key);
        if ((err = hash_memory(hash, key, keylen, hmac->key, &z)) != CRYPT_OK) {
           return err;
        }
        if(hashsize < HMAC_BLOCKSIZE) {
            zeromem((hmac->key) + hashsize, (size_t)(HMAC_BLOCKSIZE - hashsize));
        }
        keylen = hashsize;
    } else {
        memcpy(hmac->key, key, (size_t)keylen);
        if(keylen < HMAC_BLOCKSIZE) {
            zeromem((hmac->key) + keylen, (size_t)(HMAC_BLOCKSIZE - keylen));
        }
    }

    // Create the initial vector for step (3)
    for(i=0; i < HMAC_BLOCKSIZE;   i++) {
       buf[i] = hmac->key[i] ^ 0x36;
    }

    // Pre-pend that to the hash data
    hash_descriptor[hash].init(&hmac->md);
    hash_descriptor[hash].process(&hmac->md, buf, HMAC_BLOCKSIZE);

    return CRYPT_OK;
}

#endif
