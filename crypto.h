#ifndef _CRYPTO_H_

#define _CRYPTO_H_

#include "options.h"

#include "libtomcrypt/mycrypt.h"

void crypto_init();
const struct dropbear_cipher* match_cipher_list(const unsigned char *cipherlist);
const struct dropbear_hash * match_hash(const char *name);
const struct dropbear_cipher* match_cipher(const char *name);
const struct dropbear_hash* match_hash_list(const unsigned char *hashlist);

struct dropbear_cipher {

	const struct _cipher_descriptor *cipherdesc;
	unsigned long keysize;
	unsigned char blocksize;
	char *name;
	char propose; /* whether to propose the cipher at kex */

};

/* null terminated list of included ciphers */
const extern struct dropbear_cipher ciphers[];

struct dropbear_hash {

	const struct _hash_descriptor *hashdesc;
	unsigned long keysize;
	unsigned char hashsize;
	char *name;
	char propose; /* whether to propose the hash at kex */

};

/* null terminated list of included hashes */
const extern struct dropbear_hash hashes[];

#endif /* _CRYPTO_H_ */
