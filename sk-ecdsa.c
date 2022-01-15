#include "includes.h"

#if DROPBEAR_SK_ECDSA

#include "dbutil.h"
#include "ecc.h"
#include "ecdsa.h"
#include "sk-ecdsa.h"

int buf_sk_ecdsa_verify(buffer *buf, const ecc_key *key, const buffer *data_buf, const char* app, unsigned int applen) {
	/* Based on libtomcrypt's ecc_verify_hash but without the asn1 */
	int ret = DROPBEAR_FAILURE;
	hash_state hs;
	struct dropbear_ecc_curve *curve = NULL;
	unsigned char hash[64];
	unsigned char subhash[SHA256_HASH_SIZE];
	buffer *sk_buffer = NULL;
	unsigned char flags;
	unsigned int counter;
	ecc_point *mG = NULL, *mQ = NULL;
	void *r = NULL, *s = NULL, *v = NULL, *w = NULL, *u1 = NULL, *u2 = NULL,
		*e = NULL, *p = NULL, *m = NULL;
	void *mp = NULL;

	/* verify
	 *
	 * w  = s^-1 mod n
	 * u1 = xw
	 * u2 = rw
	 * X = u1*G + u2*Q
	 * v = X_x1 mod n
	 * accept if v == r
	 */

	TRACE(("buf_sk_ecdsa_verify"))
	curve = curve_for_dp(key->dp);

	mG = ltc_ecc_new_point();
	mQ = ltc_ecc_new_point();
	if (ltc_init_multi(&r, &s, &v, &w, &u1, &u2, &p, &e, &m, NULL) != CRYPT_OK
		|| !mG
		|| !mQ) {
		dropbear_exit("ECC error");
	}

	if (buf_get_ecdsa_verify_params(buf, r, s) != DROPBEAR_SUCCESS) {
		goto out;
	}

	flags = buf_getbyte (buf);
	counter = buf_getint (buf);
	sk_buffer = buf_new (2*SHA256_HASH_SIZE+5);
	sha256_init (&hs);
	sha256_process (&hs, app, applen);
	sha256_done (&hs, subhash);
	buf_putbytes (sk_buffer, subhash, sizeof (subhash));
	buf_putbyte (sk_buffer, flags);
	buf_putint (sk_buffer, counter);
	sha256_init (&hs);
	sha256_process (&hs, data_buf->data, data_buf->len);
	sha256_done (&hs, subhash);
	buf_putbytes (sk_buffer, subhash, sizeof (subhash));

	curve->hash_desc->init(&hs);
	curve->hash_desc->process(&hs, sk_buffer->data, sk_buffer->len);
	curve->hash_desc->done(&hs, hash);

	if (ltc_mp.unsigned_read(e, hash, curve->hash_desc->hashsize) != CRYPT_OK) {
		goto out;
	}

   /* get the order */
	if (ltc_mp.read_radix(p, (char *)key->dp->order, 16) != CRYPT_OK) {
		goto out;
	}

   /* get the modulus */
	if (ltc_mp.read_radix(m, (char *)key->dp->prime, 16) != CRYPT_OK) {
		goto out;
	}

   /* check for zero */
	if (ltc_mp.compare_d(r, 0) == LTC_MP_EQ
		|| ltc_mp.compare_d(s, 0) == LTC_MP_EQ
		|| ltc_mp.compare(r, p) != LTC_MP_LT
		|| ltc_mp.compare(s, p) != LTC_MP_LT) {
		goto out;
	}

   /*  w  = s^-1 mod n */
	if (ltc_mp.invmod(s, p, w) != CRYPT_OK) {
		goto out;
	}

   /* u1 = ew */
	if (ltc_mp.mulmod(e, w, p, u1) != CRYPT_OK) {
		goto out;
	}

   /* u2 = rw */
	if (ltc_mp.mulmod(r, w, p, u2) != CRYPT_OK) {
		goto out;
	}

   /* find mG and mQ */
	if (ltc_mp.read_radix(mG->x, (char *)key->dp->Gx, 16) != CRYPT_OK) {
		goto out;
	}
	if (ltc_mp.read_radix(mG->y, (char *)key->dp->Gy, 16) != CRYPT_OK) {
		goto out;
	}
	if (ltc_mp.set_int(mG->z, 1) != CRYPT_OK) {
		goto out;
	}

	if (ltc_mp.copy(key->pubkey.x, mQ->x) != CRYPT_OK
		|| ltc_mp.copy(key->pubkey.y, mQ->y) != CRYPT_OK
		|| ltc_mp.copy(key->pubkey.z, mQ->z) != CRYPT_OK) {
		goto out;
	}

   /* compute u1*mG + u2*mQ = mG */
	if (ltc_mp.ecc_mul2add == NULL) {
		if (ltc_mp.ecc_ptmul(u1, mG, mG, m, 0) != CRYPT_OK) {
			goto out;
		}
		if (ltc_mp.ecc_ptmul(u2, mQ, mQ, m, 0) != CRYPT_OK) {
			goto out;
		}

		/* find the montgomery mp */
		if (ltc_mp.montgomery_setup(m, &mp) != CRYPT_OK) {
			goto out;
		}

		/* add them */
		if (ltc_mp.ecc_ptadd(mQ, mG, mG, m, mp) != CRYPT_OK) {
			goto out;
		}

		/* reduce */
		if (ltc_mp.ecc_map(mG, m, mp) != CRYPT_OK) {
			goto out;
		}
	} else {
		/* use Shamir's trick to compute u1*mG + u2*mQ using half of the doubles */
		if (ltc_mp.ecc_mul2add(mG, u1, mQ, u2, mG, m) != CRYPT_OK) {
			goto out;
		}
	}

   /* v = X_x1 mod n */
	if (ltc_mp.mpdiv(mG->x, p, NULL, v) != CRYPT_OK) {
		goto out;
	}

   /* does v == r */
	if (ltc_mp.compare(v, r) == LTC_MP_EQ) {
		ret = DROPBEAR_SUCCESS;
	}

out:
	ltc_ecc_del_point(mG);
	ltc_ecc_del_point(mQ);
	ltc_deinit_multi(r, s, v, w, u1, u2, p, e, m, NULL);
	if (mp != NULL) {
		ltc_mp.montgomery_deinit(mp);
	}
	if (sk_buffer) {
		buf_free(sk_buffer);
	}
	return ret;
}

#endif /* DROPBEAR_SK_ECDSA */
