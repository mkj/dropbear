#include "options.h"
#include "util.h"
#include "bignum.h"
#include "dss.h"
#include "buffer.h"
#include "ssh.h"
#include "random.h"

#include "libtomcrypt/mpi.h"
#include "libtomcrypt/mycrypt.h"

#ifdef DROPBEAR_DSS 

/* Load a dss key from a buffer, initialising the values.
 * The key will have the same format as buf_put_dss_key.
 * These should be freed with dss_key_free.
 * Returns 0 on fail, -1 on success */
int buf_get_dss_pub_key(buffer* buf, dss_key *key) {

	assert(key != NULL);
	key->p = m_malloc(sizeof(mp_int));
	m_mp_init(key->p);
	key->q = m_malloc(sizeof(mp_int));
	m_mp_init(key->q);
	key->g = m_malloc(sizeof(mp_int));
	m_mp_init(key->g);
	key->y = m_malloc(sizeof(mp_int));
	m_mp_init(key->y);
	key->x = NULL;

	buf_incrpos(buf, 4+SSH_SIGNKEY_DSS_LEN); /* int + "ssh-dss" */
	if (buf_getmpint(buf, key->p) != 0
	 || buf_getmpint(buf, key->q) != 0
	 || buf_getmpint(buf, key->g) != 0
	 || buf_getmpint(buf, key->y) != 0) {
		dropbear_msg("failure reading dss pubkey");
		return -1;
	}

	return 0;
}

/* same as buf_get_dss_pub_key, but reads a private "x" key at the end.
 * Loads a private dss key from a buffer */
int buf_get_dss_priv_key(buffer* buf, dss_key *key) {

	int ret = 0;

	assert(key != NULL);

	ret = buf_get_dss_pub_key(buf, key);
	if (ret != 0) {
		goto out;
	}

	key->x = m_malloc(sizeof(mp_int));
	m_mp_init(key->x);
	ret = buf_getmpint(buf, key->x);
out:
	
	if (ret != 0) {
		dropbear_msg("failure reading dss privkey");
	}
	return ret;
}
	

/* clear and free the memory used by a public key */
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

/* put the dss key into the buffer in the required format:
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
/* returns 1 if the signature verifies, 0 otherwise */
int buf_dss_verify(buffer* buf, dss_key *key, const unsigned char* data,
		unsigned int len) {

	unsigned char msghash[SHA1_HASH_SIZE];
	hash_state hs;
	int ret = 0;
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

	m_mp_init(&val1);
	m_mp_init(&val2);
	m_mp_init(&val3);
	m_mp_init(&val4);

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
	if (mp_cmp(&val2, &val1) == 0) {
		/* good sig */
		ret = 1;
	}

out:
	mp_clear(&val1);
	mp_clear(&val2);
	mp_clear(&val3);
	mp_clear(&val4);
	m_free(string);

	return ret;

}
#endif /* DROPBEAR_SIGNKEY_VERIFY */

/* sign the data presented in len with key, writing the signature contents
 * to the buffer
 *
 * when DSS_PROTOK is #defined:
 * The alternate k generation method is based on the method used in putty. 
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

	m_mp_init(&dss_k);
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
	} while (mp_cmp(&dss_k, key->q) >= 0 || mp_cmp_z(&dss_k) <= 0);
	m_burn(kbuf, SHA1_HASH_SIZE);
#endif

	/* now generate the actual signature */
	m_mp_init(&dss_temp1);
	m_mp_init(&dss_temp2);
	m_mp_init(&dss_r);
	m_mp_init(&dss_s);
	m_mp_init(&dss_m);
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
	mp_clear(&dss_m);
	
	/* (k^-1) mod q */
	if (mp_invmod(&dss_k, key->q, &dss_temp1) != MP_OKAY) {
		dropbear_exit("dss error");
	}
	mp_clear(&dss_k);

	/* s = (k^-1(SHA1(M) + xr)) mod q */
	if (mp_mulmod(&dss_temp1, &dss_temp2, key->q, &dss_s) != MP_OKAY) {
		dropbear_exit("dss error");
	}
	mp_clear(&dss_temp1);
	mp_clear(&dss_temp2);
	
	/* create the signature to return */
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

	TRACE(("leave buf_put_dss_sign"));
}

#endif /* DROPBEAR_DSS */
