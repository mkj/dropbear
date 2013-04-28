#ifndef _ECDSA_H_
#define _ECDSA_H_

#include "includes.h"
#include "buffer.h"

#ifdef DROPBEAR_ECC_256
#define ECDSA_DEFAULT_SIZE 256
#elif DROPBEAR_ECC_384
#define ECDSA_DEFAULT_SIZE 384
#elif DROPBEAR_ECC_521
#define ECDSA_DEFAULT_SIZE 521
#else
#define ECDSA_DEFAULT_SIZE 0
#endif

ecc_key *gen_ecdsa_priv_key(unsigned int bit_size);
ecc_key *buf_get_ecdsa_pub_key(buffer* buf);
ecc_key *buf_get_ecdsa_priv_key(buffer *buf);
void buf_put_ecdsa_pub_key(buffer *buf, ecc_key *key);
void buf_put_ecdsa_priv_key(buffer *buf, ecc_key *key);

void buf_put_ecdsa_sign(buffer *buf, ecc_key *key, buffer *data_buf);
int buf_ecdsa_verify(buffer *buf, ecc_key *key, buffer *data_buf);

#endif // _ECDSA_H_