#include "options.h"
#include "libtomcrypt/mycrypt.h"
#include "util.h"

#include "crypto.h"

/* Mapping of ssh ciphers to libtomcrypt ciphers, with blocksizes etc.
 * Only compiled in ciphers are included */
/* {&cipher_desc, keysize, blocksize, name, propose} */
const struct dropbear_cipher ciphers[] = {
#ifdef DROPBEAR_AES128_CBC /* compiled with AES support */
	{&rijndael_desc, 16, 16, "aes128-cbc", 1},
#endif
#ifdef DROPBEAR_BLOWFISH_CBC /* compiled with BLOWFISH support */
	{&blowfish_desc, 16, 8, "blowfish-cbc", 1},
#endif
#ifdef DROPBEAR_3DES_CBC /* compiled 3DES */
	{&des3_desc, 24, 8, "3des-cbc", 1},
#endif
	{NULL, 16, 8, "none", 0}, /* used initially */
	{0} /* terminating */
};

/* Mapping of ssh ciphers to libtomcrypt ciphers, including keysize etc. */
/* {&hash_desc, keysize, hashsize, name, propose} */
const struct dropbear_hash hashes[] = {
#ifdef DROPBEAR_SHA1 /* compiled with SHA1 support */
	{&sha1_desc, 20, 20, "hmac-sha1", 1},
#endif
#ifdef DSS_PROTOK
	{&sha512_desc, 128, 128, "sha512", 0}, /* required for our DSS code */
#endif
	{NULL, 16, 0, "none", 0}, /* used initially */
	{0} /* terminating */
};
	
/* Register the compiled in ciphers.
 * This should be run before using any of the ciphers/hashes */
void crypto_init() {

	int i;
	
	for (i = 0; ciphers[i].cipherdesc != NULL; i++) {
		if (register_cipher(ciphers[i].cipherdesc) == -1) {
			dropbear_exit("error registering cipher"); /* TODO handling */
		}
	}

	for (i = 0; hashes[i].hashdesc != NULL; i++) {
		if (register_hash(hashes[i].hashdesc) == -1) {
			dropbear_exit("error registering cipher"); /* TODO handling */
		}
	}
}

/* hashlist is a comma seperated, null terminated list of hashes.
 * The first item in the list which also has a local entry will be chosen */
const struct dropbear_hash* match_hash_list(const unsigned char *hashlist) {

	char * algos[MAX_PROPOSED_ALGO];
	int pos1, pos2;
	int len;
	int count, i;
	char* alterlist;
	const struct dropbear_hash* ret;

	len = strlen((char*)hashlist);
	if (len > MAX_PROPOSED_ALGO*MAX_NAME_LEN) {
		return NULL;
	}
	alterlist = strdup((char*)hashlist);

	/* algos will contain a list of the strings parsed out */
	count = 0;
	pos1 = 0;
	for (pos2 = 0; pos2 <= len; pos2++) {
		if (alterlist[pos2] == ',' || alterlist[pos2] == '\0') {
			algos[count] = &alterlist[pos1];
			alterlist[pos2] = '\0';
			count++;
			pos1 = pos2+1; /* this is safe since we check pos2 next loop */
		}
		if (count == MAX_PROPOSED_ALGO) {
			break;
		}
	}

	/* iterate and find the first match supported */
	for (i = 0; i < count; i++) {
		ret = match_hash(algos[i]);
		if (ret != NULL && ret->propose) {
			m_free(alterlist);
			return ret;
		}
	}
	m_free(alterlist);
	return NULL;
}


/* cipherlist is a comma seperated, null terminated list of ciphers.
 * The first item in the list which also has a local entry will be chosen */
const struct dropbear_cipher* match_cipher_list(const unsigned char *cipherlist) {

	char * algos[MAX_PROPOSED_ALGO];
	int pos1, pos2;
	int len;
	unsigned int count, i;
	char* alterlist;
	const struct dropbear_cipher* ret;

	len = strlen((char*)cipherlist);
	if (len > MAX_PROPOSED_ALGO*MAX_NAME_LEN) {
		return NULL;
	}
	alterlist = strdup((char*)cipherlist);

	/* algos will contain a list of the strings parsed out */
	count = 0;
	pos1 = 0;
	for (pos2 = 0; pos2 <= len; pos2++) {
		if (alterlist[pos2] == ',' || alterlist[pos2] == '\0') {
			algos[count] = &alterlist[pos1];
			alterlist[pos2] = '\0';
			count++;
			pos1 = pos2+1; /* this is safe since we check pos2 next loop */
		}
		if (count == MAX_PROPOSED_ALGO) {
			break;
		}
	}

	/* iterate and find the first match supported */
	for (i = 0; i < count; i++) {
		ret = match_cipher(algos[i]);
		if (ret != NULL && ret->propose) {
			m_free(alterlist);
			return ret;
		}
	}
	m_free(alterlist);
	return NULL;
}

/* returns the identifier of the cipher corresponding to the secsh name.
 * The returned value is the libtomcrypt identifier, or -1 if not found.
 * name must be null terminated */
const struct dropbear_cipher* match_cipher(const char *name) {

	unsigned int len;
	unsigned int i;

	len = strlen(name);
	
	if (len > MAX_NAME_LEN) {
		return NULL;
	}

	for (i = 0; ciphers[i].name != NULL; i++) {
		if (strlen(ciphers[i].name) == len 
				&& strncmp(name, ciphers[i].name, len) == 0) {
			return &ciphers[i];
		}
	}
	return NULL;
}

/* returns the identifier of the hash corresponding to the secsh name.
 * The returned value is the libtomcrypt identifier, or -1 if not found.
 * name must be null terminated */
const struct dropbear_hash * match_hash(const char *name) {

	int len;
	int i;

	len = strlen(name);
	
	if (len > MAX_NAME_LEN) {
		return NULL;
	}

	for (i = 0; hashes[i].name != NULL; i++) {
		if (strlen(hashes[i].name) == len 
				&& strncmp(name, hashes[i].name, len) == 0) {
			return &hashes[i];
		}
	}
	return NULL;
}
