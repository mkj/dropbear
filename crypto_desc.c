#include "includes.h"
#include "dbutil.h"
#include "crypto_desc.h"
#include "ltc_prng.h"
#include "ecc.h"
#include "dbconfigure.h"
#include "algo.h"

static void configure_algo(char *line, char *key, algo_type* algos);

#if DROPBEAR_LTC_PRNG
	int dropbear_ltc_prng = -1;
#endif

/* Register the compiled in ciphers.
 * This should be run before using any of the ciphers/hashes */
void crypto_init() {

	const struct ltc_cipher_descriptor *regciphers[] = {
#if DROPBEAR_AES
		&aes_desc,
#endif
#if DROPBEAR_BLOWFISH
		&blowfish_desc,
#endif
#if DROPBEAR_TWOFISH
		&twofish_desc,
#endif
#if DROPBEAR_3DES
		&des3_desc,
#endif
		NULL
	};

	const struct ltc_hash_descriptor *reghashes[] = {
		/* we need sha1 for hostkey stuff regardless */
		&sha1_desc,
#if DROPBEAR_MD5_HMAC
		&md5_desc,
#endif
#if DROPBEAR_SHA256
		&sha256_desc,
#endif
#if DROPBEAR_SHA384
		&sha384_desc,
#endif
#if DROPBEAR_SHA512
		&sha512_desc,
#endif
		NULL
	};	
	int i;
	
	for (i = 0; regciphers[i] != NULL; i++) {
		if (register_cipher(regciphers[i]) == -1) {
			dropbear_exit("Error registering crypto");
		}
	}

	for (i = 0; reghashes[i] != NULL; i++) {
		if (register_hash(reghashes[i]) == -1) {
			dropbear_exit("Error registering crypto");
		}
	}

#if DROPBEAR_LTC_PRNG
	dropbear_ltc_prng = register_prng(&dropbear_prng_desc);
	if (dropbear_ltc_prng == -1) {
		dropbear_exit("Error registering crypto");
	}
#endif

#if DROPBEAR_ECC
	ltc_mp = ltm_desc;
	dropbear_ecc_fill_dp();
#endif
}

static void configure_algo(char *line, char *key, algo_type* algos)
{
	char value[32][24] = {'\0'};
	unsigned int count = 0, length;
	unsigned int n, m, found = 0;

	n = strlen(key);
	while (line[n] == ' ' || line[n] == '\t')
		n++;
	if (line[n] == '\0') {
		fprintf(stderr, "%s value is empty, skip setting.\n", key);
		return;
	}

	length = strlen(line) + 1;  /* we need to reach '\0' */
	while (n < length && line[n] == ',')
		n++;  /* eat ',' in front of value */
	m = n;
	for (; n < length; n++) {
		if (line[n] == ',') {
			strncpy(value[count], &line[m], n - m);
			value[count][sizeof(value[0])/sizeof(char) - 1] = '\0';
			while (n + 1 < length && line[n + 1] == ',')
				n++;
			m = n + 1; /* skip ',' */  
			if (++count >= sizeof(value)/sizeof(value[0])) {
				fprintf(stderr, "Too many %s value, do truncate.\n", key);
				break;
			}
		} else if (line[n] == '\0' && m != n) {
			strncpy(value[count++], &line[m], n - m);
			break;
		}	
	}
	if (count > 0) {
		for (n = 0; algos[n].name != NULL; n++) {
			algos[n].usable = 0;
			for (m = 0; m < count; m++) {
				if (!strcmp(algos[n].name, value[m])) {
					found = 1;
					algos[n].usable = 1;
				} 
			}
		}
	}
	
	/* no match algorithm, restore all to usable? */
	if (!found) {
		fprintf(stderr, "No match of %s in configuration file, skip setting.\n", key);
		for (n = 0; algos[n].name != NULL; n++) 
			algos[n].usable = 1;
	}	
}


/* Read from /etc/dropbear/crypto_config in order to use specified algorithm. 
 * Format:
 * Ciphers algo1,algo2,algo3
 * MACs algo1,algo2,algo3
 * ...
 */
void crypto_configure(const char *config_file)
{
	int i;
	int ciphers_line = -1, macs_line = -1;
	config_file_content *cfc = NULL;
	
	cfc = read_config_file(config_file);
	if (!cfc)
		return;
	
	for (i = 0; i < cfc->lines_count; i++) {
		if (!strncmp("Ciphers", cfc->lines[i], strlen("Ciphers")) && 
				strlen(cfc->lines[i]) > strlen("Ciphers") + 2) {
			ciphers_line = i;
		} else if (!strncmp("MACs", cfc->lines[i], strlen("MACs")) && 
				strlen(cfc->lines[i]) > strlen("MACs") + 2) {
			macs_line = i;
		}
	}	
	
	if (ciphers_line != -1)
		configure_algo(cfc->lines[ciphers_line], "Ciphers", sshciphers);
	if (macs_line != -1)
		configure_algo(cfc->lines[macs_line], "MACs", sshhashes);
	
	cfc->free(cfc);	
}

