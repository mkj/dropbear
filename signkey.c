/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "dbutil.h"
#include "signkey.h"
#include "buffer.h"
#include "ssh.h"

/* malloc a new sign_key and set the dss and rsa keys to NULL */
sign_key * new_sign_key() {

	sign_key * ret;

	ret = (sign_key*)m_malloc(sizeof(sign_key));
#ifdef DROPBEAR_DSS
	ret->dsskey = NULL;
#endif
#ifdef DROPBEAR_RSA
	ret->rsakey = NULL;
#endif
	return ret;

}

/* returns DROPBEAR_SUCCESS on success, DROPBEAR_FAILURE on fail */
int buf_get_pub_key(buffer *buf, sign_key *key, int type) {

	unsigned char* ident;
	unsigned int len;

	ident = buf_getstring(buf, &len);

#ifdef DROPBEAR_DSS
	if (memcmp(ident, SSH_SIGNKEY_DSS, len) == 0
			&& (type == DROPBEAR_SIGNKEY_ANY || type == DROPBEAR_SIGNKEY_DSS)) {
		m_free(ident);
		buf_setpos(buf, buf->pos - len - 4);
		dss_key_free(key->dsskey);
		key->dsskey = (dss_key*)m_malloc(sizeof(dss_key));
		return buf_get_dss_pub_key(buf, key->dsskey);
	}
#endif
#ifdef DROPBEAR_RSA
	if (memcmp(ident, SSH_SIGNKEY_RSA, len) == 0
			&& (type == DROPBEAR_SIGNKEY_ANY || type == DROPBEAR_SIGNKEY_RSA)) {
		m_free(ident);
		buf_setpos(buf, buf->pos - len - 4);
		rsa_key_free(key->rsakey);
		key->rsakey = (rsa_key*)m_malloc(sizeof(rsa_key));
		return buf_get_rsa_pub_key(buf, key->rsakey);
	}
#endif

	m_free(ident);

	return DROPBEAR_FAILURE;
	
}

/* returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_get_priv_key(buffer *buf, sign_key *key, int type) {

	unsigned char* ident;
	unsigned int len;
	int ret;

	TRACE(("enter buf_get_priv_key"));
	ident = buf_getstring(buf, &len);

#ifdef DROPBEAR_DSS
	if (memcmp(ident, SSH_SIGNKEY_DSS, len) == 0
			&& (type == DROPBEAR_SIGNKEY_ANY || type == DROPBEAR_SIGNKEY_DSS)) {
		m_free(ident);
		buf_setpos(buf, buf->pos - len - 4);
		dss_key_free(key->dsskey);
		key->dsskey = (dss_key*)m_malloc(sizeof(dss_key));
		ret = buf_get_dss_priv_key(buf, key->dsskey);
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->dsskey);
		}
		TRACE(("leave buf_get_priv_key: done get dss"));
		return ret;
	}
#endif
#ifdef DROPBEAR_RSA
	if (memcmp(ident, SSH_SIGNKEY_RSA, len) == 0
			&& (type == DROPBEAR_SIGNKEY_ANY || type == DROPBEAR_SIGNKEY_RSA)) {
		m_free(ident);
		buf_setpos(buf, buf->pos - len - 4);
		rsa_key_free(key->rsakey);
		key->rsakey = (rsa_key*)m_malloc(sizeof(rsa_key));
		ret = buf_get_rsa_priv_key(buf, key->rsakey);
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->rsakey);
		}
		TRACE(("leave buf_get_priv_key: done get rsa"));
		return ret;
	}
#endif

	m_free(ident);
	
	TRACE(("leave buf_get_priv_key"));
	return DROPBEAR_FAILURE;
	
}

/* type is either DROPBEAR_SIGNKEY_DSS or DROPBEAR_SIGNKEY_RSA */
void buf_put_pub_key(buffer* buf, sign_key *key, int type) {

	buffer *pubkeys;

	TRACE(("enter buf_put_pub_key"));
	pubkeys = buf_new(1000);
	
#ifdef DROPBEAR_DSS
	if (type == DROPBEAR_SIGNKEY_DSS) {
		buf_put_dss_pub_key(pubkeys, key->dsskey);
	}
#endif
#ifdef DROPBEAR_RSA
	if (type == DROPBEAR_SIGNKEY_RSA) {
		buf_put_rsa_pub_key(pubkeys, key->rsakey);
	}
#endif
	if (pubkeys->len == 0) {
		dropbear_exit("bad key types in buf_put_pub_key");
	}

	buf_setpos(pubkeys, 0);
	buf_putstring(buf, buf_getptr(pubkeys, pubkeys->len),
			pubkeys->len);
	
	buf_free(pubkeys);
	TRACE(("leave buf_put_pub_key"));
}

/* type is either DROPBEAR_SIGNKEY_DSS or DROPBEAR_SIGNKEY_RSA */
void buf_put_priv_key(buffer* buf, sign_key *key, int type) {

	TRACE(("enter buf_put_priv_key"));
	TRACE(("type is %d\n", type));

#ifdef DROPBEAR_DSS
	if (type == DROPBEAR_SIGNKEY_DSS) {
		buf_put_dss_priv_key(buf, key->dsskey);
	TRACE(("leave buf_put_priv_key: dss done"));
	return;
	}
#endif
#ifdef DROPBEAR_RSA
	if (type == DROPBEAR_SIGNKEY_RSA) {
		buf_put_rsa_priv_key(buf, key->rsakey);
	TRACE(("leave buf_put_priv_key: rsa done"));
	return;
	}
#endif
	dropbear_exit("bad key types in put pub key");
}

void sign_key_free(sign_key *key) {

	TRACE(("enter sign_key_free"));

#ifdef DROPBEAR_DSS
	dss_key_free(key->dsskey);
	key->dsskey = NULL;
#endif
#ifdef DROPBEAR_RSA
	rsa_key_free(key->rsakey);
	key->rsakey = NULL;
#endif

	m_free(key);
	TRACE(("leave sign_key_free"));
}

void buf_put_sign(buffer* buf, sign_key *key, int type, 
		const unsigned char *data, unsigned int len) {

	buffer *sigblob;

	sigblob = buf_new(1000);

#ifdef DROPBEAR_DSS
	if (type == DROPBEAR_SIGNKEY_DSS) {
		buf_put_dss_sign(sigblob, key->dsskey, data, len);
	}
#endif
#ifdef DROPBEAR_RSA
	if (type == DROPBEAR_SIGNKEY_RSA) {
		buf_put_rsa_sign(sigblob, key->rsakey, data, len);
	}
#endif
	if (sigblob->len == 0) {
		dropbear_exit("non-matching signing type");
	}

	buf_setpos(sigblob, 0);
	buf_putstring(buf, buf_getptr(sigblob, sigblob->len),
			sigblob->len);
			
	buf_free(sigblob);

}

#ifdef DROPBEAR_SIGNKEY_VERIFY
/* Return DROPBEAR_SUCCESS or DROPBEAR_FAILURE.
 * If FAILURE is returned, the position of
 * buf is undefined. If SUCCESS is returned, buf will be positioned after the
 * signature blob */
int buf_verify(buffer * buf, sign_key *key, const unsigned char *data,
		unsigned int len) {
	
	unsigned int bloblen;
	unsigned char * ident = NULL;
	unsigned int identlen = 0;

	bloblen = buf_getint(buf);
	ident = buf_getstring(buf, &identlen);

#ifdef DROPBEAR_DSS
	if (bloblen == DSS_SIGNATURE_SIZE &&
			memcmp(ident, SSH_SIGNKEY_DSS, identlen) == 0) {
		m_free(ident);
		return buf_dss_verify(buf, key->dsskey, data, len);
	}
#endif

#ifdef DROPBEAR_RSA
	if (memcmp(ident, SSH_SIGNKEY_RSA, identlen) == 0) {
		m_free(ident);
		return buf_rsa_verify(buf, key->rsakey, data, len);
	}
#endif

	m_free(ident);
	dropbear_exit("non-matching signing type");
	return DROPBEAR_FAILURE;
}
#endif /* DROPBEAR_SIGNKEY_VERIFY */
