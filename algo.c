#include "options.h"
#include "libtomcrypt/mycrypt.h"
#include "util.h"
#include "buffer.h"

#include "algo.h"

/* Mapping of ssh ciphers to libtomcrypt ciphers, with blocksizes etc.
   {&cipher_desc, keysize, blocksize} */

#ifdef DROPBEAR_AES128_CBC
const struct dropbear_cipher dropbear_aes128 = 
	{&rijndael_desc, 16, 16};
#endif
#ifdef DROPBEAR_BLOWFISH_CBC
const struct dropbear_cipher dropbear_blowfish = 
	{&blowfish_desc, 16, 8};
#endif
#ifdef DROPBEAR_TWOFISH128_CBC
const struct dropbear_cipher dropbear_twofish128 = 
	{&twofish_desc, 16, 16};
#endif
#ifdef DROPBEAR_3DES_CBC
const struct dropbear_cipher dropbear_3des = 
	{&des3_desc, 24, 8};
#endif

const struct dropbear_cipher dropbear_nocipher =
	{NULL, 16, 8}; /* used initially */

/* Mapping of ssh hashes to libtomcrypt hashes, including keysize etc.
   {&hash_desc, keysize, hashsize} */

#ifdef DROPBEAR_SHA1_HMAC
const struct dropbear_hash dropbear_sha1 = 
	{&sha1_desc, 20, 20};
#endif
#ifdef DROPBEAR_MD5_HMAC
const struct dropbear_hash dropbear_md5 = 
	{&md5_desc, 16, 16};
#endif

const struct dropbear_hash dropbear_nohash =
	{NULL, 16, 0}; /* used initially */
	

/* The following map ssh names to internal values */

algo_type sshciphers[] = {
#ifdef DROPBEAR_AES128_CBC
	{"aes128-cbc", 0, (void*)&dropbear_aes128, 1},
#endif
#ifdef DROPBEAR_BLOWFISH_CBC
	{"blowfish-cbc", 0, (void*)&dropbear_blowfish, 1},
#endif
#ifdef DROPBEAR_TWOFISH128_CBC
	{"twofish-cbc", 0, (void*)&dropbear_twofish128, 1},
#endif
#ifdef DROPBEAR_3DES_CBC
	{"3des-cbc", 0, (void*)&dropbear_3des, 1},
#endif
	{0}
};

algo_type sshhashes[] = {
#ifdef DROPBEAR_SHA1_HMAC
	{"hmac-sha1", 0, (void*)&dropbear_sha1, 1},
#endif
#ifdef DROPBEAR_MD5_HMAC
	{"hmac-md5", 0, (void*)&dropbear_md5, 1},
#endif
	{0}
};

algo_type sshcompress[] = {
	{"none", DROPBEAR_COMP_NONE, NULL, 1},
#ifndef DISABLE_ZLIB
	{"zlib", DROPBEAR_COMP_ZLIB, NULL, 1},
#endif
	{0}
};

algo_type sshhostkey[] = {
#ifdef DROPBEAR_RSA
	{"ssh-rsa", DROPBEAR_SIGNKEY_RSA, NULL, 1},
#endif
#ifdef DROPBEAR_DSS
	{"ssh-dss", DROPBEAR_SIGNKEY_DSS, NULL, 1},
#endif
	{0}
};

algo_type sshkex[] = {
	{"diffie-hellman-group1-sha1", DROPBEAR_KEX_DH_GROUP1, NULL, 1},
	{0}
};


/* Register the compiled in ciphers.
 * This should be run before using any of the ciphers/hashes */
void crypto_init() {

	const struct _cipher_descriptor *regciphers[] = {
#ifdef DROPBEAR_AES128_CBC
		&rijndael_desc,
#endif
#ifdef DROPBEAR_BLOWFISH_CBC
		&blowfish_desc,
#endif
#ifdef DROPBEAR_TWOFISH128_CBC
		&twofish_desc,
#endif
#ifdef DROPBEAR_3DES_CBC
		&des3_desc,
#endif
	NULL
	};

	const struct _hash_descriptor *reghashes[] = {
#ifdef DROPBEAR_SHA1_HMAC
		&sha1_desc,
#endif
#ifdef DROPBEAR_MD5_HMAC
		&md5_desc,
#endif
		NULL
	};	
	int i;
	
	for (i = 0; regciphers[i] != NULL; i++) {
		if (register_cipher(regciphers[i]) == -1) {
			dropbear_exit("error registering crypto");
		}
	}

	for (i = 0; reghashes[i] != NULL; i++) {
		if (register_hash(reghashes[i]) == -1) {
			dropbear_exit("error registering crypto");
		}
	}

	if (register_prng(&yarrow_desc) == -1) {
		dropbear_exit("error registering crypto");
	}
}

/* returns 0 if we have a match for algo, -1 otherwise */
int have_algo(char* algo, int algolen, algo_type algos[]) {

	int i = 0;
	while (algos[i].name != NULL) {
		if (strlen(algos[i].name) == algolen
				&& (strncmp(algos[i].name, algo, algolen) == 0)) {
			return 0;
		}
		i++;
	}

	return -1;
}



/* hashlist is a comma seperated, null terminated list of hashes.
 * The first item in the list which also has a local entry will be chosen */
algo_type * buf_match_algo(buffer* buf, algo_type localalgos[]) {

	unsigned char * algolist = NULL;
	unsigned char* alterlist = NULL;
	unsigned char * remotealgos[MAX_PROPOSED_ALGO];
	unsigned int pos1, pos2;
	unsigned int len;
	unsigned int count, i, j;
	algo_type * ret;

	/* get the comma-seperated list from the buffer ie "algo1,algo2,algo3" */
	algolist = buf_getstring(buf, &len);
	if (len > MAX_PROPOSED_ALGO*(MAX_NAME_LEN+1)) {
		ret = NULL;
		goto out; /* just a sanity check, no other use */
	}
	alterlist = strdup((char*)algolist);

	/* remotealgos will contain a list of the strings parsed out */
	count = 0;
	pos1 = 0;
	for (pos2 = 0; pos2 <= len; pos2++) {
		if (alterlist[pos2] == ',' || alterlist[pos2] == '\0') {
			remotealgos[count] = &alterlist[pos1];
			alterlist[pos2] = '\0';
			count++;
			pos1 = pos2+1; /* this is safe since we check pos2 next loop */
		}
		if (count == MAX_PROPOSED_ALGO) {
			break;
		}
	}

	/* iterate and find the first match */
	for (i = 0; i < count; i++) {
		len = strlen(remotealgos[i]);
		for (j = 0; localalgos[j].name != NULL; j++) {
			if (!localalgos[j].usable) {
				continue;
			}
			if (len == strlen(localalgos[j].name) 
					&& strcmp(localalgos[j].name, remotealgos[i]) == 0) {
				ret = &localalgos[j];
				goto out;
			}
		}
	}
	ret = NULL;

out:
	m_free(alterlist);
	m_free(algolist);
	return ret;
}

/* output a comma seperated list of algorithms to a buffer */
void buf_put_algolist(buffer * buf, algo_type localalgos[]) {

	unsigned int pos = 0, i, len;
	char str[50]; /* enough for local algo storage */

	for (i = 0; localalgos[i].name != NULL; i++) {
		if (localalgos[i].usable) {
			len = strlen(localalgos[i].name);
			memcpy(&str[pos], localalgos[i].name, len);
			pos += len;
			str[pos] = ',';
			pos++;
		}
	}
	buf_putstring(buf, str, pos-1);
}
