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

#include "includes.h"
#include "runopts.h"
#include "signkey.h"
#include "buffer.h"
#include "dbutil.h"
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
#ifdef DROPBEAR_DSS
					"-d dsskeyfile     Use dsskeyfile for the dss host key\n"
					"                  (default: %s)\n"
#endif
#ifdef DROPBEAR_RSA
					"-r rsakeyfile     Use rsakeyfile for the rsa host key\n"
					"                  (default: %s)\n"
#endif
					"-F                Don't fork into background\n"
#ifdef DISABLE_SYSLOG
					"(Syslog support not compiled in, using stderr)\n"
#else
					"-E                Log to stderr rather than syslog\n"
#endif
#ifdef DO_MOTD
					"-m                Don't display the motd on login\n"
#endif
					"-w                Disallow root logins\n"
					"-p port           Listen on specified tcp port, up to %d can be specified\n"
					"                  (default %d if none specified)\n"
/*					"-4/-6             Disable listening on ipv4/ipv6 respectively\n"*/

					,DROPBEAR_VERSION, progname,
#ifdef DROPBEAR_DSS
					DSS_PRIV_FILENAME,
#endif
#ifdef DROPBEAR_RSA
					RSA_PRIV_FILENAME,
#endif
					DROPBEAR_MAX_PORTS, DROPBEAR_PORT);
}

/* returns NULL on failure, or a pointer to a freshly allocated
 * runopts structure */
runopts * getrunopts(int argc, char ** argv) {

	unsigned int i;
	char ** next = 0;
	runopts * opts;
	unsigned int portnum = 0;
	char *portstring[DROPBEAR_MAX_PORTS];
	unsigned int longport;

	/* see printhelp() for options */
	opts = (runopts*)m_malloc(sizeof(runopts));
	opts->rsakeyfile = NULL;
	opts->dsskeyfile = NULL;
	opts->bannerfile = NULL;
	opts->banner = NULL;
	opts->forkbg = 1;
	opts->norootlogin = 0;
	/* not yet
	opts->ipv4 = 1;
	opts->ipv6 = 1;
	*/
#ifdef DO_MOTD
	opts->domotd = 1;
#endif
#ifndef DISABLE_SYSLOG
	usingsyslog = 1;
#endif

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
#ifdef DROPBEAR_DSS
				case 'd':
					next = &opts->dsskeyfile;
					break;
#endif
#ifdef DROPBEAR_RSA
				case 'r':
					next = &opts->rsakeyfile;
					break;
#endif
				case 'F':
					opts->forkbg = 0;
					break;
#ifndef DISABLE_SYSLOG
				case 'E':
					usingsyslog = 0;
					break;
#endif
				case 'p':
					if (portnum < DROPBEAR_MAX_PORTS) {
						portstring[portnum] = NULL;
						next = &portstring[portnum];
						portnum++;
					}
					break;
#ifdef DO_MOTD
				/* motd is displayed by default, -m turns it off */
				case 'm':
					opts->domotd = 0;
					break;
#endif
				case 'w':
					opts->norootlogin = 1;
					break;
				case 'h':
					printhelp(argv[0]);
					exit(EXIT_FAILURE);
					break;
					/*
				case '4':
					opts->ipv4 = 0;
					break;
				case '6':
					opts->ipv6 = 0;
					break;
					*/
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

	/* not yet
	if (!(opts->ipv4 || opts->ipv6)) {
		fprintf(stderr, "You can't disable ipv4 and ipv6.\n");
		exit(1);
	}
	*/

	/* create the array of listening ports */
	if (portnum == 0) {
		/* non specified */
		opts->portcount = 1;
		opts->ports = m_malloc(sizeof(uint16_t));
		opts->ports[0] = DROPBEAR_PORT;
	} else {
		opts->portcount = portnum;
		opts->ports = (uint16_t*)m_malloc(sizeof(uint16_t)*portnum);
		for (i = 0; i < portnum; i++) {
			if (portstring[i]) {
				longport = atoi(portstring[i]);
					if (longport <= 65535 && longport > 0) {
						opts->ports[i] = (uint16_t)longport;
						continue;
					}
			}
			fprintf(stderr, "Bad port '%s'\n",
					portstring[i] ? portstring[i] : "null");
		}
	}

	return opts;
}

void freerunopts(runopts* opts) {

	if (!opts) {
		return;
	}

	if (opts->hostkey) {
		sign_key_free(opts->hostkey);
		opts->hostkey = NULL;
	}

	m_free(opts->ports);
	m_free(opts);
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
		&& hostkey->rsakey == NULL
#endif
		) {
		dropbear_exit("No hostkeys available");
	}

	TRACE(("leave loadhostkeys"));
	return hostkey;
}
