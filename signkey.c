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

/* For a 4096 bit DSS key, empirically determined to be 1590 bytes */
#define MAX_PUBKEY_SIZE 1600

/* The max size of a sigblob is 529 for RSA-4096bit, or ~143 for DSA-4096  */
#define MAX_SIGBLOB  550

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

/* returns DROPBEAR_SUCCESS on success, DROPBEAR_FAILURE on fail.
 * type is set to hold the type returned */
int buf_get_pub_key(buffer *buf, sign_key *key, int *type) {

	unsigned char* ident;
	unsigned int len;

	ident = buf_getstring(buf, &len);

#ifdef DROPBEAR_DSS
	if (memcmp(ident, SSH_SIGNKEY_DSS, len) == 0
			&& (*type == DROPBEAR_SIGNKEY_ANY 
				|| *type == DROPBEAR_SIGNKEY_DSS)) {
		m_free(ident);
		buf_setpos(buf, buf->pos - len - 4);
		dss_key_free(key->dsskey);
		key->dsskey = (dss_key*)m_malloc(sizeof(dss_key));
		*type = DROPBEAR_SIGNKEY_DSS;
		return buf_get_dss_pub_key(buf, key->dsskey);
	}
#endif
#ifdef DROPBEAR_RSA
	if (memcmp(ident, SSH_SIGNKEY_RSA, len) == 0
			&& (*type == DROPBEAR_SIGNKEY_ANY 
				|| *type == DROPBEAR_SIGNKEY_RSA)) {
		m_free(ident);
		buf_setpos(buf, buf->pos - len - 4);
		rsa_key_free(key->rsakey);
		key->rsakey = (rsa_key*)m_malloc(sizeof(rsa_key));
		*type = DROPBEAR_SIGNKEY_RSA;
		return buf_get_rsa_pub_key(buf, key->rsakey);
	}
#endif

	m_free(ident);

	return DROPBEAR_FAILURE;
	
}

/* returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
/* type is set to hold the type returned */
int buf_get_priv_key(buffer *buf, sign_key *key, int *type) {

	unsigned char* ident;
	unsigned int len;
	int ret;

	TRACE(("enter buf_get_priv_key"));
	ident = buf_getstring(buf, &len);

#ifdef DROPBEAR_DSS
	if (memcmp(ident, SSH_SIGNKEY_DSS, len) == 0
			&& (*type == DROPBEAR_SIGNKEY_ANY 
				|| *type == DROPBEAR_SIGNKEY_DSS)) {
		m_free(ident);
		buf_setpos(buf, buf->pos - len - 4);
		dss_key_free(key->dsskey);
		key->dsskey = (dss_key*)m_malloc(sizeof(dss_key));
		ret = buf_get_dss_priv_key(buf, key->dsskey);
		*type = DROPBEAR_SIGNKEY_DSS;
		if (ret == DROPBEAR_FAILURE) {
			m_free(key->dsskey);
		}
		TRACE(("leave buf_get_priv_key: done get dss"));
		return ret;
	}
#endif
#ifdef DROPBEAR_RSA
	if (memcmp(ident, SSH_SIGNKEY_RSA, len) == 0
			&& (*type == DROPBEAR_SIGNKEY_ANY 
				|| *type == DROPBEAR_SIGNKEY_RSA)) {
		m_free(ident);
		buf_setpos(buf, buf->pos - len - 4);
		rsa_key_free(key->rsakey);
		key->rsakey = (rsa_key*)m_malloc(sizeof(rsa_key));
		ret = buf_get_rsa_priv_key(buf, key->rsakey);
		*type = DROPBEAR_SIGNKEY_RSA;
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
	pubkeys = buf_new(MAX_PUBKEY_SIZE);
	
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
	TRACE(("type is %d", type));

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

static char hexdig(unsigned char x) {

	if (x > 0xf)
		return 'X';

	if (x < 10)
		return '0' + x;
	else
		return 'a' + x - 10;
}

/* Since we're not sure if we'll have md5 or sha1, we present both.
 * MD5 is used in preference, but sha1 could still be useful */
#ifdef DROPBEAR_MD5_HMAC
static char * sign_key_md5_fingerprint(sign_key *key, int type) {

	char * ret;
	hash_state hs;
	buffer *pubkeys;
	unsigned char hash[MD5_HASH_SIZE];
	unsigned int h, i;
	unsigned int buflen;

	md5_init(&hs);

	pubkeys = buf_new(MAX_PUBKEY_SIZE);
	buf_put_pub_key(pubkeys, key, type);
	/* skip the size int of the string - this is a bit messy */
	buf_setpos(pubkeys, 4);
	md5_process(&hs, buf_getptr(pubkeys, pubkeys->len-pubkeys->pos),
			pubkeys->len-pubkeys->pos);

	buf_free(pubkeys);
	md5_done(&hs, hash);

	/* "md5 hexfingerprinthere\0", each hex digit is "AB:" etc */
	buflen = 4 + 3*MD5_HASH_SIZE;
	ret = (char*)m_malloc(buflen);

	memset(ret, 'Z', buflen);
	strcpy(ret, "md5 ");

	/* print the hexadecimal */
	for (i = 4, h = 0; i < buflen; i+=3, h++) {
		ret[i] = hexdig(hash[h] >> 4);
		ret[i+1] = hexdig(hash[h] & 0x0f);
		ret[i+2] = ':';
	}
	ret[buflen-1] = 0x0;

	return ret;
}

#else /* use SHA1 rather than MD5 for fingerprint */
static char * sign_key_sha1_fingerprint(sign_key *key, int type) {

	char * ret;
	hash_state hs;
	buffer *pubkeys;
	unsigned char hash[SHA1_HASH_SIZE];
	unsigned int h, i;
	unsigned int buflen;

	sha1_init(&hs);

	pubkeys = buf_new(MAX_PUBKEY_SIZE);
	buf_put_pub_key(pubkeys, key, type);
	buf_setpos(pubkeys, 4);
	/* skip the size int of the string - this is a bit messy */
	sha1_process(&hs, buf_getptr(pubkeys, pubkeys->len-pubkeys->pos),
			pubkeys->len-pubkeys->pos);

	buf_free(pubkeys);
	sha1_done(&hs, hash);

	/* "sha1 hexfingerprinthere\0", each hex digit is "AB:" etc */
	buflen = 5 + 3*SHA1_HASH_SIZE;
	ret = (char*)m_malloc(buflen);

	strcpy(ret, "sha1 ");

	for (i = 5, h = 0; i < buflen; i+=3, h++) {
		ret[i] = hexdig(hash[h] >> 4);
		ret[i+1] = hexdig(hash[h] & 0x0f);
		ret[i+2] = ':';
	}
	ret[buflen-1] = 0x0;

	return ret;
}

#endif /* MD5/SHA1 switch */

/* This will return a freshly malloced string, containing a fingerprint
 * in either sha1 or md5 */
char * sign_key_fingerprint(sign_key *key, int type) {

#ifdef DROPBEAR_MD5_HMAC
	return sign_key_md5_fingerprint(key, type);
#else
	return sign_key_sha1_fingerprint(key, type);
#endif
}

void buf_put_sign(buffer* buf, sign_key *key, int type, 
		const unsigned char *data, unsigned int len) {

	buffer *sigblob;

	sigblob = buf_new(MAX_SIGBLOB);

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
