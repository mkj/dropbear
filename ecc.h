#ifndef _DROPBEAR_ECC_H
#define _DROPBEAR_ECC_H

#include "includes.h"
#include "options.h"

#include "buffer.h"

#ifdef DROPBEAR_ECC

struct dropbear_ecc_curve {
	const ltc_ecc_set_type *dp; // curve domain parameters
	const struct ltc_hash_descriptor *hash_desc;
	const char *name;
};

extern const struct dropbear_ecc_curve ecc_curve_nistp256;
extern const struct dropbear_ecc_curve ecc_curve_nistp384;
extern const struct dropbear_ecc_curve ecc_curve_nistp521;

// "pubkey" refers to a point, but LTC uses ecc_key structure for both public
// and private keys
void buf_put_ecc_raw_pubkey_string(buffer *buf, ecc_key *key);
ecc_key * buf_get_ecc_raw_pubkey(buffer *buf, const struct dropbear_ecc_curve *curve);
int buf_get_ecc_privkey_string(buffer *buf, ecc_key *key);

mp_int * dropbear_ecc_shared_secret(ecc_key *pub_key, ecc_key *priv_key);

#endif

#endif // _DROPBEAR_ECC_H