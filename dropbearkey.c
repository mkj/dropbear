#include "options.h"
#include "runopts.h"
#include "signkey.h"
#include "buffer.h"
#include "util.h"

#include "genrsa.h"
#include "gendss.h"

static void printhelp(char * progname);

#define BUF_SIZE 2000

#define RSA_SIZE (1024/8) /* 1024 bit */
#define DSS_SIZE (1024/8) /* 1024 bit */

static void buf_writefile(buffer * buf, const char * filename);
static void printhelp(char * progname) {

	fprintf(stderr, "Usage: %s -t <type> -f <filename> [-s bits]\n"
					"Options are:\n"
					"-t type           Type of key to generate. One of:\n"
#ifdef DROPBEAR_RSA
					"                  rsa\n"
#endif
#ifdef DROPBEAR_DSS
					"                  dss\n"
#endif
					"-f filename       Use filename for the secret key\n"
					"-s bits           Key size in bits, should be "
					"multiple of 8 (optional)\n",
					progname);
}

int main(int argc, char ** argv) {

	int i;
	char ** next = 0;
	sign_key *key;
	buffer *buf;
	char * filename = NULL;
	int keytype = -1;
	char * typetext = NULL;
	char * sizetext = NULL;
	unsigned int bits;
	unsigned int keysize;

	/* get the commandline options */
	for (i = 1; i < argc; i++) {
		if (next) {
			*next = argv[i];
			if (*next == NULL) {
				fprintf(stderr, "Invalid null argument");
			}
			next = 0x00;
			continue;
		}

		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
				case 'f':
					next = &filename;
					break;
				case 't':
					next = &typetext;
					break;
				case 's':
					next = &sizetext;
					break;
				case 'h':
					printhelp(argv[0]);
					exit(EXIT_SUCCESS);
					break;
				default:
					fprintf(stderr, "Unknown argument %s\n", argv[i]);
					printhelp(argv[0]);
					exit(EXIT_FAILURE);
					break;
			}
		}
	}

	/* check/parse args */
	if (!typetext) {
		fprintf(stderr, "Must specify file type, one of:\n"
#ifdef DROPBEAR_RSA
				"rsa\n"
#endif
#ifdef DROPBEAR_DSS
				"dss\n"
#endif
			   );
		printhelp(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (strlen(typetext) == 3) {
#ifdef DROPBEAR_RSA
		if (strncmp(typetext, "rsa", 3) == 0) {
			keytype = DROPBEAR_SIGNKEY_RSA;
			TRACE(("type is rsa"));
		}
#endif
#ifdef DROPBEAR_DSS
		if (strncmp(typetext, "dss", 3) == 0) {
			keytype = DROPBEAR_SIGNKEY_DSS;
			TRACE(("type is dss"));
		}
#endif
	}
	if (keytype == -1) {
		fprintf(stderr, "Unknown key type '%s'\n", typetext);
		printhelp(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (sizetext) {
		if (sscanf(sizetext, "%u", &bits) != 1) {
			fprintf(stderr, "Bits must be an integer\n");
			exit(EXIT_FAILURE);
		}
	
		if (bits < 512 || bits > 4096 || (bits % 8 != 0)) {
			fprintf(stderr, "Bits must satisfy 512 <= bits <= 4096, and be a"
					" multiple of 8\n");
			exit(EXIT_FAILURE);
		}

		keysize = bits / 8;
	} else {
		if (keytype == DROPBEAR_SIGNKEY_DSS) {
			keysize = DSS_SIZE;
		} else if (keytype == DROPBEAR_SIGNKEY_RSA) {
			keysize = RSA_SIZE;
		} else {
			exit(EXIT_FAILURE); /* not reached */
		}
	}

	if (!filename) {
		fprintf(stderr, "Must specify a key filename\n");
		printhelp(argv[0]);
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "Will output %d bit %s secret key to '%s'\n", keysize*8,
			typetext, filename);

	/* now we can generate the key */
	key = new_sign_key();
	
	fprintf(stderr, "Generating key, this may take a while...\n");
	switch(keytype) {
#ifdef DROPBEAR_RSA
		case DROPBEAR_SIGNKEY_RSA:
			key->rsakey = gen_rsa_priv_key(keysize); /* 128 bytes = 1024 bit */
			break;
#endif
#ifdef DROPBEAR_DSS
		case DROPBEAR_SIGNKEY_DSS:
			key->dsskey = gen_dss_priv_key(keysize); /* 128 bytes = 1024 bit */
			break;
#endif
		default:
			fprintf(stderr, "Internal error, bad key type\n");
			exit(EXIT_FAILURE);
	}

	buf = buf_new(BUF_SIZE); 

	buf_put_priv_key(buf, key, keytype);
	buf_setpos(buf, 0);
	buf_writefile(buf, filename);

	buf_burn(buf);
	buf_free(buf);
	sign_key_free(key);

	fprintf(stderr, "Done.\n");

	return EXIT_SUCCESS;
}

static void buf_writefile(buffer * buf, const char * filename) {

	int fd;
	int len;

	fd = open(filename, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "Couldn't create new file %s\n", filename);
		perror("Reason");
		buf_burn(buf);
		exit(EXIT_FAILURE);
	}

	/* write the file now */
	while (buf->pos != buf->len) {
		len = write(fd, buf_getptr(buf, buf->len - buf->pos),
				buf->len - buf->pos);
		if (errno == EINTR) {
			continue;
		}
		if (len <= 0) {
			fprintf(stderr, "Failed writing file '%s'\n",filename);
			perror("Reason");
			exit(EXIT_FAILURE);
		}
		buf_incrpos(buf, len);
	}

	close(fd);
}
