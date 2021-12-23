#ifndef DROPBEAR_SK_ECDSA_H_
#define DROPBEAR_SK_ECDSA_H_

#include "includes.h"
#include "buffer.h"
#include "signkey.h"

#if DROPBEAR_SK_ECDSA

int buf_sk_ecdsa_verify(buffer *buf, const ecc_key *key, const buffer *data_buf, const char* app, unsigned int applen);
int signkey_is_sk_ecdsa(enum signkey_type type);

#endif

#endif /* DROPBEAR_SK_ECDSA_H_ */
