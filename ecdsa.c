#include "includes.h"
#include "dbutil.h"
#include "crypto_desc.h"

#ifdef DROPBEAR_ECDSA

ecc_key *gen_ecdsa_priv_key(unsigned int bit_size) {
	const ltc_ecc_set_type *dp = NULL; // curve domain parameters
	// TODO: use raw bytes for the dp rather than the hex strings in libtomcrypt's ecc.c
	switch (bit_size) {
#ifdef DROPBEAR_ECC_256
		case 256:
			dp = &ltc_ecc_sets[0];
			break;
#endif
#ifdef DROPBEAR_ECC_384
		case 384:
			dp = &ltc_ecc_sets[0];
			break;
#endif
#ifdef DROPBEAR_ECC_521
		case 521:
			dp = &ltc_ecc_sets[0];
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

int buf_get_ecdsa_pub_key(buffer* buf, ecc_key *key) {

}


#endif // DROPBEAR_ECDSA
