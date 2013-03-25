#ifdef DROPBEAR_ECC

void buf_put_ecc_key_string(buffer *buf, ecc_key *key) {
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


#endif
