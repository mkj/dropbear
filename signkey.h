#ifndef _SIGNKEY_H_
#define _SIGNKEY_H_

#include "buffer.h"
#include "dss.h"
#include "rsa.h"

struct SIGN_key {

#ifdef DROPBEAR_DSS
	dss_key * dsskey;
#endif
#ifdef DROPBEAR_RSA
	rsa_key * rsakey;
#endif
};

typedef struct SIGN_key sign_key;

sign_key * new_sign_key();
int buf_get_pub_key(buffer *buf, sign_key *key, int type);
int buf_get_priv_key(buffer* buf, sign_key *key, int type);
void buf_put_pub_key(buffer* buf, sign_key *key, int type);
void buf_put_priv_key(buffer* buf, sign_key *key, int type);
void sign_key_free(sign_key *key);
void buf_put_sign(buffer* buf, sign_key *key, int type, 
		const unsigned char *data, unsigned int len);
#ifdef DROPBEAR_SIGNKEY_VERIFY
int buf_verify(buffer * buf, sign_key *key, const unsigned char *data,
		unsigned int len);
#endif

#endif /* _SIGNKEY_H_ */
