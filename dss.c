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
#include "bignum.h"
#include "dss.h"
#include "buffer.h"
#include "ssh.h"
#include "random.h"

/* Handle DSS (Digital Signature Standard), aka DSA (D.S. Algorithm),
 * operations, such as key reading, signing, verification. Key generation
 * is in gendss.c, since it isn't required in the server itself.
 *
 * See FIPS186 or the Handbook of Applied Cryptography for details of the
 * algorithm */

#ifdef DROPBEAR_DSS 

/* Load a dss key from a buffer, initialising the values.
 * The key will have the same format as buf_put_dss_key.
 * These should be freed with dss_key_free.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_get_dss_pub_key(buffer* buf, dss_key *key) {

	assert(key != NULL);
	key->p = m_malloc(sizeof(mp_int));
	key->q = m_malloc(sizeof(mp_int));
	key->g = m_malloc(sizeof(mp_int));
	key->y = m_malloc(sizeof(mp_int));
	m_mp_init_multi(key->p, key->q, key->g, key->y, NULL);
	key->x = NULL;

	buf_incrpos(buf, 4+SSH_SIGNKEY_DSS_LEN); /* int + "ssh-dss" */
	if (buf_getmpint(buf, key->p) == DROPBEAR_FAILURE
	 || buf_getmpint(buf, key->q) == DROPBEAR_FAILURE
	 || buf_getmpint(buf, key->g) == DROPBEAR_FAILURE
	 || buf_getmpint(buf, key->y) == DROPBEAR_FAILURE) {
		return DROPBEAR_FAILURE;
	}

	return DROPBEAR_SUCCESS;
}

/* Same as buf_get_dss_pub_key, but reads a private "x" key at the end.
 * Loads a private dss key from a buffer
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_get_dss_priv_key(buffer* buf, dss_key *key) {

	int ret = DROPBEAR_FAILURE;

	assert(key != NULL);

	ret = buf_get_dss_pub_key(buf, key);
	if (ret == DROPBEAR_FAILURE) {
		return DROPBEAR_FAILURE;
	}

	key->x = m_malloc(sizeof(mp_int));
	m_mp_init(key->x);
	ret = buf_getmpint(buf, key->x);

	return ret;
}
	

/* Clear and free the memory used by a public or private key */
void dss_key_free(dss_key *key) {

	TRACE(("enter dsa_key_free"));
	if (key == NULL) {
		TRACE(("enter dsa_key_free: key == NULL"));
		return;
	}
	if (key->p) {
		mp_clear(key->p);
		m_free(key->p);
	}
	if (key->q) {
		mp_clear(key->q);
		m_free(key->q);
	}
	if (key->g) {
		mp_clear(key->g);
		m_free(key->g);
	}
	if (key->y) {
		mp_clear(key->y);
		m_free(key->y);
	}
	if (key->x) {
		mp_clear(key->x);
		m_free(key->x);
	}
	m_free(key);
	TRACE(("leave dsa_key_free"));
}

/* put the dss public key into the buffer in the required format:
 *
 * string	"ssh-dss"
 * mpint	p
 * mpint	q
 * mpint	g
 * mpint	y
 */
void buf_put_dss_pub_key(buffer* buf, dss_key *key) {

	assert(key != NULL);
	buf_putstring(buf, SSH_SIGNKEY_DSS, SSH_SIGNKEY_DSS_LEN);
	buf_putmpint(buf, key->p);
	buf_putmpint(buf, key->q);
	buf_putmpint(buf, key->g);
	buf_putmpint(buf, key->y);

}

/* Same as buf_put_dss_pub_key, but with the private "x" key appended */
void buf_put_dss_priv_key(buffer* buf, dss_key *key) {

	assert(key != NULL);
	buf_put_dss_pub_key(buf, key);
	buf_putmpint(buf, key->x);

}

#ifdef DROPBEAR_SIGNKEY_VERIFY
/* Verify a DSS signature (in buf) made on data by the key given. 
 * returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_dss_verify(buffer* buf, dss_key *key, const unsigned char* data,
		unsigned int len) {

	unsigned char msghash[SHA1_HASH_SIZE];
	hash_state hs;
	int ret = DROPBEAR_FAILURE;
	mp_int val1, val2, val3, val4;
	char * string = NULL;
	int stringlen;

	TRACE(("enter buf_dss_verify"));
	assert(key != NULL);

	/* get blob, check length */
	string = buf_getstring(buf, &stringlen);
	if (stringlen != 2*SHA1_HASH_SIZE) {
		goto out;
	}

	/* hash the data */
	sha1_init(&hs);
	sha1_process(&hs, data, len);
	sha1_done(&hs, msghash);

	m_mp_init_multi(&val1, &val2, &val3, &val4, NULL);

	/* create the signature - s' and r' are the received signatures in buf */
	/* w = (s')-1 mod q */
	/* let val1 = s' */
	if (mp_read_unsigned_bin(&val1, &string[SHA1_HASH_SIZE], SHA1_HASH_SIZE)
			!= MP_OKAY) {
		goto out;
	}
	/* let val2 = w = (s')^-1 mod q*/
	if (mp_invmod(&val1, key->q, &val2) != MP_OKAY) {
		goto out;
	}

	/* u1 = ((SHA(M')w) mod q */
	/* let val1 = SHA(M') = msghash */
	if (mp_read_unsigned_bin(&val1, msghash, SHA1_HASH_SIZE) != MP_OKAY) {
		goto out;
	}
	/* let val3 = u1 = ((SHA(M')w) mod q */
	if (mp_mulmod(&val1, &val2, key->q, &val3) != MP_OKAY) {
		goto out;
	}

	/* u2 = ((r')w) mod q */
	/* let val1 = r' */
	if (mp_read_unsigned_bin(&val1, &string[0], SHA1_HASH_SIZE)
			!= MP_OKAY) {
		goto out;
	}
	/* let val4 = u2 = ((r')w) mod q */
	if (mp_mulmod(&val1, &val2, key->q, &val4) != MP_OKAY) {
		goto out;
	}

	/* v = (((g)^u1 (y)^u2) mod p) mod q */
	/* val2 = g^u1 mod p */
	if (mp_exptmod(key->g, &val3, key->p, &val2) != MP_OKAY) {
		goto out;
	}
	/* val3 = y^u2 mod p */
	if (mp_exptmod(key->y, &val4, key->p, &val3) != MP_OKAY) {
		goto out;
	}
	/* val4 = ((g)^u1 (y)^u2) mod p */
	if (mp_mulmod(&val2, &val3, key->p, &val4) != MP_OKAY) {
		goto out;
	}
	/* val2 = v = (((g)^u1 (y)^u2) mod p) mod q */
	if (mp_mod(&val4, key->q, &val2) != MP_OKAY) {
		goto out;
	}
	
	/* check whether signatures verify */
	if (mp_cmp(&val2, &val1) == MP_EQ) {
		/* good sig */
		ret = DROPBEAR_SUCCESS;
	}

out:
	mp_clear_multi(&val1, &val2, &val3, &val4, NULL);
	m_free(string);

	return ret;

}
#endif /* DROPBEAR_SIGNKEY_VERIFY */

/* Sign the data presented with key, writing the signature contents
 * to the buffer
 *
 * When DSS_PROTOK is #defined:
 * The alternate k generation method is based on the method used in PuTTY. 
 * In particular to avoid being vulnerable to attacks using flaws in random
 * generation of k, we use the following:
 *
 * proto_k = SHA512 ( SHA512(x) || SHA160(message) )
 * k = proto_k mod q
 *
 * Now we aren't relying on the random number generation to protect the private
 * key x, which is a long term secret */
void buf_put_dss_sign(buffer* buf, dss_key *key, const unsigned char* data,
		unsigned int len) {

	unsigned char msghash[SHA1_HASH_SIZE];
	unsigned int writelen;
	unsigned int i;
#ifdef DSS_PROTOK
	unsigned char privkeyhash[SHA512_HASH_SIZE];
	unsigned char *privkeytmp;
	unsigned char proto_k[SHA512_HASH_SIZE];
	mp_int dss_protok;
#else
	unsigned char kbuf[SHA1_HASH_SIZE];
#endif
	mp_int dss_k, dss_m;
	mp_int dss_temp1, dss_temp2;
	mp_int dss_r, dss_s;
	hash_state hs;
	
	TRACE(("enter buf_put_dss_sign"));
	assert(key != NULL);
	
	/* hash the data */
	sha1_init(&hs);
	sha1_process(&hs, data, len);
	sha1_done(&hs, msghash);

	m_mp_init_multi(&dss_k, &dss_temp1, &dss_temp2, &dss_r, &dss_s,
			&dss_m, NULL);
#ifdef DSS_PROTOK	
	/* hash the privkey */
	privkeytmp = mptobytes(key->x, &i);
	sha512_init(&hs);
	sha512_process(&hs, "the quick brown fox jumped over the lazy dog", 44);
	sha512_process(&hs, privkeytmp, i);
	sha512_done(&hs, privkeyhash);
	m_burn(privkeytmp, i);
	m_free(privkeytmp);

	/* calculate proto_k */
	sha512_init(&hs);
	sha512_process(&hs, privkeyhash, SHA512_HASH_SIZE);
	sha512_process(&hs, msghash, SHA1_HASH_SIZE);
	sha512_done(&hs, proto_k);

	/* generate k */
	m_mp_init(&dss_protok);
	bytestomp(&dss_protok, proto_k, SHA512_HASH_SIZE);
	mp_mod(&dss_protok, key->q, &dss_k);
	mp_clear(&dss_protok);
	m_burn(proto_k, SHA512_HASH_SIZE);
#else /* DSS_PROTOK not defined*/
	do {
		genrandom(kbuf, SHA1_HASH_SIZE);
		if (mp_read_unsigned_bin(&dss_k, kbuf, SHA1_HASH_SIZE) != MP_OKAY) {
			dropbear_exit("dss error");
		}
	} while (mp_cmp(&dss_k, key->q) == MP_GT || mp_cmp_d(&dss_k, 0) != MP_GT);
	m_burn(kbuf, SHA1_HASH_SIZE);
#endif

	/* now generate the actual signature */
	bytestomp(&dss_m, msghash, SHA1_HASH_SIZE);

	/* g^k mod p */
	if (mp_exptmod(key->g, &dss_k, key->p, &dss_temp1) !=  MP_OKAY) {
		dropbear_exit("dss error");
	}
	/* r = (g^k mod p) mod q */
	if (mp_mod(&dss_temp1, key->q, &dss_r) != MP_OKAY) {
		dropbear_exit("dss error");
	}

	/* x*r mod q */
	if (mp_mulmod(&dss_r, key->x, key->q, &dss_temp1) != MP_OKAY) {
		dropbear_exit("dss error");
	}
	/* (SHA1(M) + xr) mod q) */
	if (mp_addmod(&dss_m, &dss_temp1, key->q, &dss_temp2) != MP_OKAY) {
		dropbear_exit("dss error");
	}
	
	/* (k^-1) mod q */
	if (mp_invmod(&dss_k, key->q, &dss_temp1) != MP_OKAY) {
		dropbear_exit("dss error");
	}

	/* s = (k^-1(SHA1(M) + xr)) mod q */
	if (mp_mulmod(&dss_temp1, &dss_temp2, key->q, &dss_s) != MP_OKAY) {
		dropbear_exit("dss error");
	}

	buf_putstring(buf, SSH_SIGNKEY_DSS, SSH_SIGNKEY_DSS_LEN);
	buf_putint(buf, 2*SHA1_HASH_SIZE);

	writelen = mp_unsigned_bin_size(&dss_r);
	assert(writelen <= SHA1_HASH_SIZE);
	/* need to pad to 160 bits with leading zeros */
	for (i = 0; i < SHA1_HASH_SIZE - writelen; i++) {
		buf_putbyte(buf, 0);
	}
	if (mp_to_unsigned_bin(&dss_r, buf_getwriteptr(buf, writelen)) 
			!= MP_OKAY) {
		dropbear_exit("dss error");
	}
	mp_clear(&dss_r);
	buf_incrwritepos(buf, writelen);

	writelen = mp_unsigned_bin_size(&dss_s);
	assert(writelen <= SHA1_HASH_SIZE);
	/* need to pad to 160 bits with leading zeros */
	for (i = 0; i < SHA1_HASH_SIZE - writelen; i++) {
		buf_putbyte(buf, 0);
	}
	if (mp_to_unsigned_bin(&dss_s, buf_getwriteptr(buf, writelen)) 
			!= MP_OKAY) {
		dropbear_exit("dss error");
	}
	mp_clear(&dss_s);
	buf_incrwritepos(buf, writelen);

	mp_clear_multi(&dss_k, &dss_temp1, &dss_temp1, &dss_r, &dss_s,
			&dss_m, NULL);
	
	/* create the signature to return */

	TRACE(("leave buf_put_dss_sign"));
}

#endif /* DROPBEAR_DSS */
