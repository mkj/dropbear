/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "algo.h"
#include "dbutil.h"

/* This file (algo.c) organises the ciphers which can be used, and is used to
 * decide which ciphers/hashes/compression/signing to use during key exchange*/

/* Mappings for ciphers, parameters are
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

/* used to indicate no encryption, as defined in rfc2410 */
const struct dropbear_cipher dropbear_nocipher =
	{NULL, 16, 8}; 

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
	{NULL, 0, NULL, 0}
};

algo_type sshhashes[] = {
#ifdef DROPBEAR_SHA1_HMAC
	{"hmac-sha1", 0, (void*)&dropbear_sha1, 1},
#endif
#ifdef DROPBEAR_MD5_HMAC
	{"hmac-md5", 0, (void*)&dropbear_md5, 1},
#endif
	{NULL, 0, NULL, 0}
};

algo_type sshcompress[] = {
	{"none", DROPBEAR_COMP_NONE, NULL, 1},
#ifndef DISABLE_ZLIB
	{"zlib", DROPBEAR_COMP_ZLIB, NULL, 1},
#endif
	{NULL, 0, NULL, 0}
};

algo_type sshhostkey[] = {
#ifdef DROPBEAR_RSA
	{"ssh-rsa", DROPBEAR_SIGNKEY_RSA, NULL, 1},
#endif
#ifdef DROPBEAR_DSS
	{"ssh-dss", DROPBEAR_SIGNKEY_DSS, NULL, 1},
#endif
	{NULL, 0, NULL, 0}
};

algo_type sshkex[] = {
	{"diffie-hellman-group1-sha1", DROPBEAR_KEX_DH_GROUP1, NULL, 1},
	{NULL, 0, NULL, 0}
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
		/* we need sha1 for hostkey stuff regardless */
		&sha1_desc,
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
}

/* algolen specifies the length of algo, algos is our local list to match
 * against.
 * Returns DROPBEAR_SUCCESS if we have a match for algo, DROPBEAR_FAILURE
 * otherwise */
int have_algo(char* algo, size_t algolen, algo_type algos[]) {

	int i;

	for (i = 0; algos[i].name != NULL; i++) {
		if (strlen(algos[i].name) == algolen
				&& (strncmp(algos[i].name, algo, algolen) == 0)) {
			return DROPBEAR_SUCCESS;
		}
	}

	return DROPBEAR_FAILURE;
}


/* match the first algorithm in the comma-seperated list in buf which is
 * also in localalgos[], or return NULL on failure. */
algo_type * buf_match_algo(buffer* buf, algo_type localalgos[]) {

	unsigned char * algolist = NULL;
	unsigned char * remotealgos[MAX_PROPOSED_ALGO];
	unsigned int len;
	unsigned int count, i, j;
	algo_type * ret = NULL;

	/* get the comma-seperated list from the buffer ie "algo1,algo2,algo3" */
	algolist = buf_getstring(buf, &len);
	if (len > MAX_PROPOSED_ALGO*(MAX_NAME_LEN+1)) {
		goto out; /* just a sanity check, no other use */
	}

	/* remotealgos will contain a list of the strings parsed out */
	/* We will have at least one string (even if it's just "") */
	remotealgos[0] = algolist;
	count = 1;
	/* Iterate through, replacing ','s with NULs, to split it into
	 * words. */
	for (i = 0; i < len; i++) {
		if (algolist[i] == '\0') {
			/* someone is trying something strange */
			goto out;
		}
		if (algolist[i] == ',') {
			algolist[i] = '\0';
			remotealgos[count] = &algolist[i+1];
			count++;
		}
		if (count == MAX_PROPOSED_ALGO) {
			break;
		}
	}

	/* iterate and find the first match */
	for (i = 0; i < count; i++) {

		len = strlen(remotealgos[i]);

		for (j = 0; localalgos[j].name != NULL; j++) {
			if (localalgos[j].usable) {
				if (len == strlen(localalgos[j].name) 
						&& strncmp(localalgos[j].name, 
							remotealgos[i], len) == 0) {
					ret = &localalgos[j];
					goto out;
				}
			}
		}
	}

out:
	m_free(algolist);
	return ret;
}

/* Output a comma seperated list of algorithms to a buffer */
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
