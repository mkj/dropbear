#ifndef _RSA_H_
#define _RSA_H_

#include "buffer.h"

#ifdef DROPBEAR_RSA 

#define RSA_SIGNATURE_SIZE 4+7+4+40

struct RSA_key {

	mp_int* n;
	mp_int* e;
	mp_int* d;

};

typedef struct RSA_key rsa_key;

void buf_put_rsa_sign(buffer* buf, rsa_key *key, const unsigned char* data,
		unsigned int len);
#ifdef DROPBEAR_SIGNKEY_VERIFY
int buf_rsa_verify(buffer * buf, rsa_key *key, const unsigned char* data,
		unsigned int len);
#endif
int buf_get_rsa_pub_key(buffer* buf, rsa_key *key);
int buf_get_rsa_priv_key(buffer* buf, rsa_key *key);
void buf_put_rsa_pub_key(buffer* buf, rsa_key *key);
void buf_put_rsa_priv_key(buffer* buf, rsa_key *key);
void rsa_key_free(rsa_key *key);

#endif /* DROPBEAR_RSA */

#endif /* _RSA_H_ */
