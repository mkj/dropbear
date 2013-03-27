#include "includes.h"
#include "options.h"
#include "ecc.h"

#ifdef DROPBEAR_ECC

// TODO: use raw bytes for the dp rather than the hex strings in libtomcrypt's ecc.c

#ifdef DROPBEAR_ECC_256
const struct dropbear_ecc_curve ecc_curve_secp256r1 {
	.dp = &ltc_ecc_sets[0],
	.hash_desc = sha256_desc,
	.name = "secp256r1"
};
#endif


#ifdef DROPBEAR_ECC_384
const struct dropbear_ecc_curve ecc_curve_secp384r1 {
	.dp = &ltc_ecc_sets[1],
	.hash_desc = sha384_desc,
	.name = "secp384r1"
};
#endif

#ifdef DROPBEAR_ECC_521
const struct dropbear_ecc_curve ecc_curve_secp521r1 {
	.dp = &ltc_ecc_sets[2],
	.hash_desc = sha521_desc,
	.name = "secp521r1"
};
#endif


void buf_put_ecc_pubkey_string(buffer *buf, ecc_key *key) {
	// XXX point compression
	int len = key->dp->size*2 + 1;
	buf_putint(len);
	int err = ecc_ansi_x963_export(key, buf_getwriteptr(buf, len), &len);
	if (err != CRYPT_OK) {
		dropbear_exit("ECC error");
	}
	buf_incrwritepos(buf, len);
}

ecc_key * buf_get_ecc_key_string(buffer *buf, const struct dropbear_ecc_curve *curve) {
   ecc_key *key = NULL;
   int ret = DROPBEAR_FAILURE;
   const int size = curve->dp->size;
   unsigned int len = buf_get_string(buf);
   unsigned char first = buf_get_char(buf);
   if (first == 2 || first == 3) {
      dropbear_log("Dropbear doesn't support ECC point compression");
      return NULL;
   }
   if (first != 4 || len != 1+2*size) {
      return NULL;
   }

   key = m_malloc(sizeof(*key));
   m_mp_init_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, NULL);

   if (mp_read_unsigned_bin(&key->pubkey.x, buf_getptr(buf, size), size) != MP_OKAY) {
      goto out;
   }
   buf_incrpos(buf, size);

   if (mp_read_unsigned_bin(&key->pubkey.y, buf_getptr(buf, size), size) != MP_OKAY) {
      goto out;
   }
   buf_incrpos(buf, size);

   if (mp_set(key->pubkey.z, 1) != MP_OKAY) {
      goto out;
   }

   if (is_point(key) != CRYPT_OK) {
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
         mp_free_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k, NULL);
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
