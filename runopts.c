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

#include "options.h"
#include "runopts.h"
#include "signkey.h"
#include "buffer.h"
#include "util.h"
#include "algo.h"

static sign_key * loadhostkeys(const char * dsskeyfile,
		const char * rsakeyfile);
static int readhostkey(const char * filename, sign_key * hostkey, int type);
static void printhelp(const char * progname);

static void printhelp(const char * progname) {

	fprintf(stderr, "Dropbear v%s\n"
					"Usage: %s [options]\n"
					"Options are:\n"
					"-b bannerfile     Display the contents of bannerfile"
					" before user login\n"
					"                  (default: none)\n"
					"-d dsskeyfile     Use dsskeyfile for the dss host key\n"
					"                  (default: %s)\n"
					"-r rsakeyfile     Use rsakeyfile for the rsa host key\n"
					"                  (default: %s)\n"
					"-F                Don't fork into background\n"
					"-p port           Listen on specified tcp port\n"
					"                  (default %d)\n",
					DROPBEAR_VERSION,
					progname, DSS_PRIV_FILENAME, RSA_PRIV_FILENAME,
					DROPBEAR_PORT);
}

/* returns NULL on failure, or a pointer to a freshly allocated
 * runopts structure */
runopts * getrunopts(int argc, char ** argv) {

	int i;
	char ** next = 0;
	runopts * opts;
	char * portstring = NULL;
	unsigned int longport;

	/* see printhelp() for options */
	opts = (runopts*)m_malloc(sizeof(runopts));
	opts->rsakeyfile = NULL;
	opts->dsskeyfile = NULL;
	opts->bannerfile = NULL;
	opts->banner = NULL;
	opts->forkbg = 1;

	for (i = 1; i < argc; i++) {
		if (next) {
			*next = argv[i];
			if (*next == NULL) {
				dropbear_exit("Invalid null argument");
			}
			next = 0x00;
			continue;
		}

		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
				case 'b':
					next = &opts->bannerfile;
					break;
				case 'd':
					next = &opts->dsskeyfile;
					break;
				case 'r':
					next = &opts->rsakeyfile;
					break;
				case 'F':
					opts->forkbg = 0;
					break;
				case 'p':
					next = &portstring;
					break;
				case 'h':
					printhelp(argv[0]);
					exit(EXIT_FAILURE);
					break;
				default:
					fprintf(stderr, "Unknown argument %s\n", argv[i]);
					printhelp(argv[0]);
					exit(EXIT_FAILURE);
					break;
			}
		}
	}

	if (opts->dsskeyfile == NULL) {
		opts->dsskeyfile = DSS_PRIV_FILENAME;
	}
	if (opts->rsakeyfile == NULL) {
		opts->rsakeyfile = RSA_PRIV_FILENAME;
	}
	opts->hostkey = loadhostkeys(opts->dsskeyfile, opts->rsakeyfile);

	if (opts->bannerfile) {
		struct stat buf;
		if (stat(opts->bannerfile, &buf) != 0) {
			dropbear_exit("Error opening banner file '%s'",
					opts->bannerfile);
		}
		
		if (buf.st_size > MAX_BANNER_SIZE) {
			dropbear_exit("Banner file too large, max is %d bytes",
					MAX_BANNER_SIZE);
		}

		opts->banner = buf_new(buf.st_size);
		if (buf_readfile(opts->banner, opts->bannerfile)!=DROPBEAR_SUCCESS) {
			dropbear_exit("Error reading banner file '%s'",
					opts->bannerfile);
		}
		buf_setpos(opts->banner, 0);
	}

	if (portstring) {
		longport = atoi(portstring);
		if (longport > 65534 || longport < 1) {
			dropbear_exit("Bad port %s", portstring);
		}
		opts->port = (uint16_t)longport;
	} else {
		opts->port = DROPBEAR_PORT;
	}

	return opts;
}

/* returns success or failure */
static int readhostkey(const char * filename, sign_key * hostkey, int type) {

	int ret = DROPBEAR_FAILURE;
	int i;
	buffer *buf;

	buf = buf_new(2000);

	if (buf_readfile(buf, filename) == DROPBEAR_FAILURE) {
		goto out;
	}
	buf_setpos(buf, 0);
	if (buf_get_priv_key(buf, hostkey, type) == DROPBEAR_FAILURE) {
		goto out;
	}

	ret = DROPBEAR_SUCCESS;
out:
	if (ret == DROPBEAR_FAILURE) {
		for (i = 0; sshhostkey[i].name != NULL; i++) {
			if (sshhostkey[i].val == type) {
				sshhostkey[i].usable = 0;
				break;
			}
		}
		fprintf(stderr, "Failed reading '%s', disabling %s\n", filename,
				type == DROPBEAR_SIGNKEY_DSS ? "DSS" : "RSA");
	}

	buf_burn(buf);
	buf_free(buf);
	return ret;
}

static sign_key * loadhostkeys(const char * dsskeyfile, 
		const char * rsakeyfile) {

	sign_key * hostkey;

	TRACE(("enter loadhostkeys"));

	hostkey = new_sign_key();

#ifdef DROPBEAR_RSA
	(void)readhostkey(rsakeyfile, hostkey, DROPBEAR_SIGNKEY_RSA);
#endif

#ifdef DROPBEAR_DSS
	(void)readhostkey(dsskeyfile, hostkey, DROPBEAR_SIGNKEY_DSS);
#endif

	if ( 1
#ifdef DROPBEAR_DSS
		&& hostkey->dsskey == NULL
#endif
#ifdef DROPBEAR_RSA
		&& hostkey->rsakey == NULL)
#endif
		{
		dropbear_exit("No hostkeys available");
	}

	TRACE(("leave loadhostkeys"));
	return hostkey;
}
