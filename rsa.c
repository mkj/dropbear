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

#include "options.h"
#include "util.h"
#include "bignum.h"
#include "rsa.h"
#include "buffer.h"
#include "ssh.h"
#include "random.h"

#include "libtomcrypt/mycrypt.h"

#ifdef DROPBEAR_RSA 

static mp_int * rsa_pad_em(rsa_key * key,
		const unsigned char * data, unsigned int len);

/* Load a rsa key from a buffer, initialising the values.
 * The key will have the same format as buf_put_rsa_key.
 * These should be freed with rsa_key_free.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_get_rsa_pub_key(buffer* buf, rsa_key *key) {

	TRACE(("enter buf_get_rsa_pub_key"));
	assert(key != NULL);
	key->e = m_malloc(sizeof(mp_int));
	m_mp_init(key->e);
	key->n = m_malloc(sizeof(mp_int));
	m_mp_init(key->n);
	key->d = NULL;

	buf_incrpos(buf, 4+SSH_SIGNKEY_RSA_LEN); /* int + "ssh-rsa" */

	if (buf_getmpint(buf, key->e) == DROPBEAR_FAILURE
	 || buf_getmpint(buf, key->n) == DROPBEAR_FAILURE) {
		TRACE(("leave buf_get_rsa_pub_key: failure"));
		return DROPBEAR_FAILURE;
	}
	TRACE(("leave buf_get_rsa_pub_key: success"));
	return DROPBEAR_SUCCESS;

}

/* same as buf_get_rsa_pub_key, but reads a private "x" key at the end.
 * Loads a private rsa key from a buffer
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_get_rsa_priv_key(buffer* buf, rsa_key *key) {

	assert(key != NULL);

	TRACE(("enter buf_get_rsa_priv_key"));

	if (buf_get_rsa_pub_key(buf, key) == DROPBEAR_FAILURE) {
		TRACE(("leave buf_get_rsa_priv_key: pub: ret == DROPBEAR_FAILURE"));
		return DROPBEAR_FAILURE;
	}

	key->d = m_malloc(sizeof(mp_int));
	m_mp_init(key->d);
	if (buf_getmpint(buf, key->d) == DROPBEAR_FAILURE) {
		TRACE(("leave buf_get_rsa_priv_key: d: ret == DROPBEAR_FAILURE"));
		return DROPBEAR_FAILURE;
	}

	/* old Dropbear private keys didn't keep p and q, so we will ignore them*/
	if (buf->pos == buf->len) {
		key->p = NULL;
		key->q = NULL;
	} else {
		key->p = m_malloc(sizeof(mp_int));
		m_mp_init(key->p);
		if (buf_getmpint(buf, key->p) == DROPBEAR_FAILURE) {
			TRACE(("leave buf_get_rsa_priv_key: p: ret == DROPBEAR_FAILURE"));
			return DROPBEAR_FAILURE;
		}

		key->q = m_malloc(sizeof(mp_int));
		m_mp_init(key->q);
		if (buf_getmpint(buf, key->q) == DROPBEAR_FAILURE) {
			TRACE(("leave buf_get_rsa_priv_key: q: ret == DROPBEAR_FAILURE"));
			return DROPBEAR_FAILURE;
		}
	}

	TRACE(("leave buf_get_rsa_priv_key"));
	return DROPBEAR_SUCCESS;
}
	

/* clear and free the memory used by a public key */
void rsa_key_free(rsa_key *key) {

	TRACE(("enter rsa_key_free"));

	if (key == NULL) {
		TRACE(("leave rsa_key_free: key == NULL"));
		return;
	}
	if (key->d) {
		mp_clear(key->d);
		m_free(key->d);
	}
	if (key->e) {
		mp_clear(key->e);
		m_free(key->e);
	}
	if (key->n) {
		 mp_clear(key->n);
		 m_free(key->n);
	}
	m_free(key);
	TRACE(("leave rsa_key_free"));
}

/* put the rsa key into the buffer in the required format:
 *
 * string	"ssh-rsa"
 * mp_int	e
 * mp_int	n
 */
void buf_put_rsa_pub_key(buffer* buf, rsa_key *key) {

	TRACE(("enter buf_put_rsa_pub_key"));
	assert(key != NULL);

	buf_putstring(buf, SSH_SIGNKEY_RSA, SSH_SIGNKEY_RSA_LEN);
	buf_putmpint(buf, key->e);
	buf_putmpint(buf, key->n);

	TRACE(("leave buf_put_rsa_pub_key"));

}

/* Same as buf_put_rsa_pub_key, but with the private "x" key appended */
void buf_put_rsa_priv_key(buffer* buf, rsa_key *key) {

	TRACE(("enter buf_put_rsa_priv_key"));

	assert(key != NULL);
	buf_put_rsa_pub_key(buf, key);
	buf_putmpint(buf, key->d);

	/* new versions have p and q, old versions don't */
	if (key->p) {
		buf_putmpint(buf, key->p);
	}
	if (key->q) {
		buf_putmpint(buf, key->p);
	}


	TRACE(("leave buf_put_rsa_priv_key"));

}

#ifdef DROPBEAR_SIGNKEY_VERIFY
/* returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_rsa_verify(buffer * buf, rsa_key *key, const unsigned char* data,
		unsigned int len) {

	unsigned int slen;
	mp_int rsa_s, rsa_mdash;
	mp_int *rsa_em = NULL;
	int ret = DROPBEAR_FAILURE;

	assert(key != NULL);

	m_mp_init(&rsa_mdash);
	m_mp_init(&rsa_s);

	slen = buf_getint(buf);
	if (slen != mp_unsigned_bin_size(key->n)) {
		TRACE(("bad size"));
		goto out;
	}

	if (mp_read_unsigned_bin(&rsa_s, buf_getptr(buf, buf->len - buf->pos),
				buf->len - buf->pos) != MP_OKAY) {
		goto out;
	}

	/* create the magic PKCS padded value */
	rsa_em = rsa_pad_em(key, data, len);

	if (mp_exptmod(&rsa_s, key->e, key->n, &rsa_mdash) != MP_OKAY) {
		goto out;
	}

	if (mp_cmp(rsa_em, &rsa_mdash) == 0) {
		/* signature is valid */
		ret = DROPBEAR_SUCCESS;
	}

out:
	mp_clear(rsa_em);
	m_free(rsa_em);
	mp_clear(&rsa_mdash);
	mp_clear(&rsa_s);
	return ret;

}
#endif /* DROPBEAR_SIGNKEY_VERIFY */

/* sign the data presented with key, writing the signature contents
 * to the buffer */
void buf_put_rsa_sign(buffer* buf, rsa_key *key, const unsigned char* data,
		unsigned int len) {

	unsigned int nsize, ssize;
	unsigned int i;
	mp_int rsa_s;
	mp_int *rsa_em;
	
	TRACE(("enter buf_put_rsa_sign"));
	assert(key != NULL);

	rsa_em = rsa_pad_em(key, data, len);

	/* the actual signing of the padded data */
	m_mp_init(&rsa_s);
	/* s = em^d mod n */
	if (mp_exptmod(rsa_em, key->d, key->n, &rsa_s) != MP_OKAY) {
		dropbear_exit("rsa error");
	}
	mp_clear(rsa_em);
	m_free(rsa_em);
	
	/* create the signature to return */
	buf_putstring(buf, SSH_SIGNKEY_RSA, SSH_SIGNKEY_RSA_LEN);

	nsize = mp_unsigned_bin_size(key->n);

	/* string rsa_signature_blob length */
	buf_putint(buf, nsize);
	/* pad out s to same length as n */
	ssize = mp_unsigned_bin_size(&rsa_s);
	assert(ssize <= nsize);
	for (i = 0; i < nsize-ssize; i++) {
		buf_putbyte(buf, 0x00);
	}

	if (mp_to_unsigned_bin(&rsa_s, buf_getwriteptr(buf, ssize)) != MP_OKAY) {
		dropbear_exit("rsa error");
	}
	buf_incrwritepos(buf, ssize);
	mp_clear(&rsa_s);

#if defined(DEBUG_RSA) && defined(DEBUG_TRACE)
	printhex(buf->data, buf->len);
#endif
	

	TRACE(("leave buf_put_rsa_sign"));
}

/* creates the message value as expected by PKCS, see rfc2437 etc */
/* format to be padded to is:
 * EM = 01 | FF* | 00 | prefix | hash
 *
 * where FF is repeated enough times to make EM one byte
 * shorter than the size of key->n
 *
 * prefix is the ASN1 designator prefix,
 * hex 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14
 */
static mp_int * rsa_pad_em(rsa_key * key,
		const unsigned char * data, unsigned int len) {

	const char rsa_asn1_magic[] = 
		{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 
		 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
#define RSA_ASN1_MAGIC_LEN 15
	buffer * rsa_EM;
	hash_state hs;
	unsigned int nsize;
	mp_int * rsa_em;
	unsigned int i;
	
	assert(key != NULL);
	assert(data != NULL);
	nsize = mp_unsigned_bin_size(key->n);

	rsa_EM = buf_new(nsize-1);
	buf_putbyte(rsa_EM, 0x01);
	for (i = 0; i < (nsize-1)-SHA1_HASH_SIZE-2-RSA_ASN1_MAGIC_LEN; i++) {
		buf_putbyte(rsa_EM, 0xff);
	}
	buf_putbyte(rsa_EM, 0x00);
	memcpy(buf_getwriteptr(rsa_EM, RSA_ASN1_MAGIC_LEN),
			rsa_asn1_magic, RSA_ASN1_MAGIC_LEN);
	buf_incrwritepos(rsa_EM, RSA_ASN1_MAGIC_LEN);

	/* hash the data */
	sha1_init(&hs);
	sha1_process(&hs, data, len);
	sha1_done(&hs, buf_getwriteptr(rsa_EM, SHA1_HASH_SIZE));
	buf_incrwritepos(rsa_EM, SHA1_HASH_SIZE);
	assert(rsa_EM->pos == rsa_EM->size);

	buf_setpos(rsa_EM, 0);
	rsa_em = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(rsa_em);
	if (mp_read_unsigned_bin(rsa_em, buf_getptr(rsa_EM, rsa_EM->size),
				rsa_EM->size) != MP_OKAY) {
		dropbear_exit("rsa error");
	}
	buf_free(rsa_EM);

	return rsa_em;

}

#endif /* DROPBEAR_RSA */
