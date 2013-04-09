#include "includes.h"
#include "dbutil.h"
#include "crypto_desc.h"
#include "ecc.h"

#ifdef DROPBEAR_ECDSA

ecc_key *gen_ecdsa_priv_key(unsigned int bit_size) {
	const ltc_ecc_set_type *dp = NULL; // curve domain parameters
	// TODO: use raw bytes for the dp rather than the hex strings in libtomcrypt's ecc.c
	switch (bit_size) {
#ifdef DROPBEAR_ECC_256
		case 256:
			dp = ecc_curve_nistp256.dp;
			break;
#endif
#ifdef DROPBEAR_ECC_384
		case 384:
			dp = ecc_curve_nistp384.dp;
			break;
#endif
#ifdef DROPBEAR_ECC_521
		case 521:
			dp = ecc_curve_nistp521.dp;
			break;
#endif
	}
	if (!dp) {
		dropbear_exit("Key size %d isn't valid. Try "
#ifdef DROPBEAR_ECC_256
			"256 "
#endif
#ifdef DROPBEAR_ECC_384
			"384 "
#endif
#ifdef DROPBEAR_ECC_521
			"521 "
#endif
			, bit_size);
	}

	ecc_key *new_key = m_malloc(sizeof(*new_key));
	if (ecc_make_key_ex(NULL, dropbear_ltc_prng, new_key, dp) != CRYPT_OK) {
		dropbear_exit("ECC error");
	}
	return new_key;
}

ecc_key *buf_get_ecdsa_pub_key(buffer* buf) {
	unsigned char *key_ident = NULL, *identifier = NULL;
	unsigned int key_ident_len, identifier_len;
	buffer *q_buf = NULL;
	struct dropbear_ecc_curve **curve;
	ecc_key *new_key = NULL;

	// string   "ecdsa-sha2-[identifier]"
	key_ident = buf_getstring(buf, &key_ident_len);
	// string   "ecdsa-sha2-[identifier]"
	identifier = buf_getstring(buf, &identifier_len);

	if (key_ident_len != identifier_len + strlen("ecdsa-sha2-")) {
		TRACE(("Bad identifier lengths"))
		goto out;
	}
	if (memcmp(&key_ident[strlen("ecdsa-sha2-")], identifier, identifier_len) != 0) {
		TRACE(("mismatching identifiers"))
		goto out;
	}

	for (curve = dropbear_ecc_curves; *curve; curve++) {
		if (memcmp(identifier, (*curve)->name, strlen((*curve)->name)) == 0) {
			break;
		}
	}
	if (!*curve) {
		TRACE(("couldn't match ecc curve"))
		goto out;
	}

	// string Q
	q_buf = buf_getstringbuf(buf);
	new_key = buf_get_ecc_raw_pubkey(q_buf, *curve);

out:
	if (key_ident) {
		m_free(key_ident);
	}
	if (identifier) {
		m_free(identifier);
	}
	if (q_buf) {
		buf_free(q_buf);
		q_buf = NULL;
	}
	TRACE(("leave buf_get_ecdsa_pub_key"))	
	return new_key;
}


#endif // DROPBEAR_ECDSA
