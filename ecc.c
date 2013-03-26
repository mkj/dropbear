#include "includes.h"
#include "options.h"
#include "ecc.h"

#ifdef DROPBEAR_ECC

#ifdef DROPBEAR_ECC_256
const struct ecc_curve_secp256r1 {
	.ltc_set = &ltc_ecc_sets[0],
	.hash_desc = sha256_desc,
	.name = "secp256r1"
};
#endif


#ifdef DROPBEAR_ECC_384
const struct ecc_curve_secp384r1 {
	.ltc_set = &ltc_ecc_sets[1],
	.hash_desc = sha384_desc,
	.name = "secp384r1"
};
#endif

#ifdef DROPBEAR_ECC_256
const struct ecc_curve_secp256r1 {
	.ltc_set = &ltc_ecc_sets[0],
	.hash_desc = sha256_desc,
	.name = "secp256r1"
};
#endif


void buf_put_ecc_key_string(buffer *buf, ecc_key *key) {
	// XXX point compression
	int len = key->dp->size*2 + 1;
	buf_putint(len);
	int err = ecc_ansi_x963_export(key, buf_getwriteptr(buf, len), &len);
	if (err != CRYPT_OK) {
		dropbear_exit("ECC error");
	}
	buf_incrwritepos(buf, len);
}

int buf_get_ecc_key_string(buffer *buf, ecc_key *key) {
}

// a modified version of libtomcrypt's "ecc_shared_secret" to output
// a mp_int instead.
mp_int * dropbear_ecc_shared_secret(ecc_key *public_key, ecc_key *private_key)
{
   ecc_point *result = NULL
   mp_int *prime = NULL, *shared_secret = NULL;
   int ret = DROPBEAR_FAILURE;

   /* type valid? */
   if (private_key->type != PK_PRIVATE) {
   	goto done;
   }

   if (private_key->dp != public_key->dp) {
   	goto done;
   }

#if 0
   // XXX - possibly not neccessary tests?
   if (ltc_ecc_is_valid_idx(private_key->idx) == 0 || ltc_ecc_is_valid_idx(public_key->idx) == 0) {
   	goto done;
   }

   if (XSTRCMP(private_key->dp->name, public_key->dp->name) != 0) {
   	goto done;
   }
#endif

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
		shared_secret = prime;
		prime = NULL;
	}

	if (prime) {
	   mp_clear(prime);
	   m_free(prime);
	}
   ltc_ecc_del_point(result);

   if (err == DROPBEAR_FAILURE) {
   	 dropbear_exit("ECC error");
   }

   return shared_secret;
   return err;
}

}

#endif
