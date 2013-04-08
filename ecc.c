#include "includes.h"
#include "options.h"
#include "ecc.h"
#include "dbutil.h"
#include "bignum.h"

#ifdef DROPBEAR_ECC

// TODO: use raw bytes for the dp rather than the hex strings in libtomcrypt's ecc.c
#ifdef DROPBEAR_ECC_256
const struct dropbear_ecc_curve ecc_curve_nistp256 = {
	.dp = &ltc_ecc_sets[0],
	.hashdesc = &sha256_desc,
	.name = "nistp256"
};
#endif
#ifdef DROPBEAR_ECC_384
const struct dropbear_ecc_curve ecc_curve_nistp384 = {
	.dp = &ltc_ecc_sets[1],
	.hashdesc = &sha384_desc,
	.name = "nistp384"
};
#endif
#ifdef DROPBEAR_ECC_521
const struct dropbear_ecc_curve ecc_curve_nistp521 = {
	.dp = &ltc_ecc_sets[2],
	.hashdesc = &sha512_desc,
	.name = "nistp521"
};
#endif

static ecc_key * new_ecc_key(void) {
	ecc_key *key = m_malloc(sizeof(*key));
	key->pubkey.x = m_malloc(sizeof(mp_int));
	key->pubkey.y = m_malloc(sizeof(mp_int));
	key->pubkey.z = m_malloc(sizeof(mp_int));
	key->k = m_malloc(sizeof(mp_int));
	m_mp_init_multi(key->pubkey.x, key->pubkey.y, key->pubkey.z, key->k, NULL);
	return key;
}

// Copied from libtomcrypt ecc_import.c (version there is static), modified
// for different mp_int pointer without LTC_SOURCE
static int ecc_is_point(ecc_key *key)
{
	mp_int *prime, *b, *t1, *t2;
	int err;

	prime = m_malloc(sizeof(mp_int));
	b = m_malloc(sizeof(mp_int));
	t1 = m_malloc(sizeof(mp_int));
	t2 = m_malloc(sizeof(mp_int));
	
	m_mp_init_multi(prime, b, t1, t2, NULL);
	
   /* load prime and b */
	if ((err = mp_read_radix(prime, key->dp->prime, 16)) != CRYPT_OK)                          { goto error; }
	if ((err = mp_read_radix(b, key->dp->B, 16)) != CRYPT_OK)                                  { goto error; }
	
   /* compute y^2 */
	if ((err = mp_sqr(key->pubkey.y, t1)) != CRYPT_OK)                                         { goto error; }
	
   /* compute x^3 */
	if ((err = mp_sqr(key->pubkey.x, t2)) != CRYPT_OK)                                         { goto error; }
	if ((err = mp_mod(t2, prime, t2)) != CRYPT_OK)                                             { goto error; }
	if ((err = mp_mul(key->pubkey.x, t2, t2)) != CRYPT_OK)                                     { goto error; }
	
   /* compute y^2 - x^3 */
	if ((err = mp_sub(t1, t2, t1)) != CRYPT_OK)                                                { goto error; }
	
   /* compute y^2 - x^3 + 3x */
	if ((err = mp_add(t1, key->pubkey.x, t1)) != CRYPT_OK)                                     { goto error; }
	if ((err = mp_add(t1, key->pubkey.x, t1)) != CRYPT_OK)                                     { goto error; }
	if ((err = mp_add(t1, key->pubkey.x, t1)) != CRYPT_OK)                                     { goto error; }
	if ((err = mp_mod(t1, prime, t1)) != CRYPT_OK)                                             { goto error; }
	while (mp_cmp_d(t1, 0) == LTC_MP_LT) {
		if ((err = mp_add(t1, prime, t1)) != CRYPT_OK)                                          { goto error; }
	}
	while (mp_cmp(t1, prime) != LTC_MP_LT) {
		if ((err = mp_sub(t1, prime, t1)) != CRYPT_OK)                                          { goto error; }
	}
	
   /* compare to b */
	if (mp_cmp(t1, b) != LTC_MP_EQ) {
		err = CRYPT_INVALID_PACKET;
	} else {
		err = CRYPT_OK;
	}
	
	error:
	mp_clear_multi(prime, b, t1, t2, NULL);
	m_free(prime);
	m_free(b);
	m_free(t1);
	m_free(t2);
	return err;
}

/* For the "ephemeral public key octet string" in ECDH (rfc5656 section 4) */
void buf_put_ecc_raw_pubkey_string(buffer *buf, ecc_key *key) {
	unsigned long len = key->dp->size*2 + 1;
	buf_putint(buf, len);
	int err = ecc_ansi_x963_export(key, buf_getwriteptr(buf, len), &len);
	if (err != CRYPT_OK) {
		dropbear_exit("ECC error");
	}
	buf_incrwritepos(buf, len);
}

/* For the "ephemeral public key octet string" in ECDH (rfc5656 section 4) */
ecc_key * buf_get_ecc_raw_pubkey(buffer *buf, const struct dropbear_ecc_curve *curve) {
	ecc_key *key = NULL;
	int ret = DROPBEAR_FAILURE;
	const unsigned int size = curve->dp->size;
	buf_setpos(buf, 0);
	unsigned int len = buf->len;
	unsigned char first = buf_getbyte(buf);
	if (first == 2 || first == 3) {
		dropbear_log(LOG_WARNING, "Dropbear doesn't support ECC point compression");
		return NULL;
	}
	if (first != 4 || len != 1+2*size) {
		return NULL;
	}

	key = new_ecc_key();
	key->dp = curve->dp;

	if (mp_read_unsigned_bin(key->pubkey.x, buf_getptr(buf, size), size) != MP_OKAY) {
		goto out;
	}
	buf_incrpos(buf, size);

	if (mp_read_unsigned_bin(key->pubkey.y, buf_getptr(buf, size), size) != MP_OKAY) {
		goto out;
	}
	buf_incrpos(buf, size);

	mp_set(key->pubkey.z, 1);

	if (ecc_is_point(key) != CRYPT_OK) {
		goto out;
	}

   // SEC1 3.2.3.1 Check that Q != 0
	if (mp_cmp_d(key->pubkey.x, 0) == LTC_MP_EQ) {
		goto out;
	}
	if (mp_cmp_d(key->pubkey.y, 0) == LTC_MP_EQ) {
		goto out;
	}

	ret = DROPBEAR_SUCCESS;

	out:
	if (ret == DROPBEAR_FAILURE) {
		if (key) {
			ecc_free(key);
			m_free(key);
			key = NULL;
		}
	}

	return key;

}

// a modified version of libtomcrypt's "ecc_shared_secret" to output
// a mp_int instead.
mp_int * dropbear_ecc_shared_secret(ecc_key *public_key, ecc_key *private_key)
{
	ecc_point *result = NULL;
	mp_int *prime = NULL, *shared_secret = NULL;
	int err = DROPBEAR_FAILURE;

   /* type valid? */
	if (private_key->type != PK_PRIVATE) {
		goto done;
	}

	if (private_key->dp != public_key->dp) {
		goto done;
	}

   /* make new point */
	result = ltc_ecc_new_point();
	if (result == NULL) {
		goto done;
	}

	prime = m_malloc(sizeof(*prime));
	m_mp_init(prime);

	if (mp_read_radix(prime, (char *)private_key->dp->prime, 16) != CRYPT_OK) { 
		goto done; 
	}
	if (ltc_mp.ecc_ptmul(private_key->k, &public_key->pubkey, result, prime, 1) != CRYPT_OK) { 
		goto done; 
	}

	err = DROPBEAR_SUCCESS;
	done:
	if (err == DROPBEAR_SUCCESS) {
		shared_secret = m_malloc(sizeof(*shared_secret));
		m_mp_init(shared_secret);
		mp_copy(result->x, shared_secret);
	}

	if (prime) {
		mp_clear(prime);
		m_free(prime);
	}
	if (result)
	{
		ltc_ecc_del_point(result);
	}

	if (err == DROPBEAR_FAILURE) {
		dropbear_exit("ECC error");
	}
	return shared_secret;
}

#endif
