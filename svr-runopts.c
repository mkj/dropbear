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

svr_runopts svr_opts; /* GLOBAL */

static sign_key * loadhostkeys(const char * dsskeyfile,
		const char * rsakeyfile);
static void printhelp(const char * progname);

static void printhelp(const char * progname) {

	fprintf(stderr, "Dropbear sshd v%s\n"
					"Usage: %s [options]\n"
					"Options are:\n"
					"-b bannerfile	Display the contents of bannerfile"
					" before user login\n"
					"		(default: none)\n"
#ifdef DROPBEAR_DSS
					"-d dsskeyfile	Use dsskeyfile for the dss host key\n"
					"		(default: %s)\n"
#endif
#ifdef DROPBEAR_RSA
					"-r rsakeyfile	Use rsakeyfile for the rsa host key\n"
					"		(default: %s)\n"
#endif
					"-F		Don't fork into background\n"
#ifdef DISABLE_SYSLOG
					"(Syslog support not compiled in, using stderr)\n"
#else
					"-E		Log to stderr rather than syslog\n"
#endif
#ifdef DO_MOTD
					"-m		Don't display the motd on login\n"
#endif
					"-w		Disallow root logins\n"
#ifdef ENABLE_SVR_PASSWORD_AUTH
					"-s		Disable password logins\n"
					"-g		Disable password logins for root\n"
#endif
#ifndef DISABLE_LOCALTCPFWD
					"-j		Disable local port forwarding\n"
#endif
#ifndef DISABLE_REMOTETCPFWD
					"-k		Disable remote port forwarding\n"
#endif
					"-p port	Listen on specified tcp port, up to %d can be specified\n"
					"		(default %d if none specified)\n"
/*					"-4/-6		Disable listening on ipv4/ipv6 respectively\n"*/

					,DROPBEAR_VERSION, progname,
#ifdef DROPBEAR_DSS
					DSS_PRIV_FILENAME,
#endif
#ifdef DROPBEAR_RSA
					RSA_PRIV_FILENAME,
#endif
					DROPBEAR_MAX_PORTS, DROPBEAR_PORT);
}

void svr_getopts(int argc, char ** argv) {

	unsigned int i;
	char ** next = 0;
	unsigned int portnum = 0;
	char *portstring[DROPBEAR_MAX_PORTS];
	unsigned int longport;

	/* see printhelp() for options */
	svr_opts.rsakeyfile = NULL;
	svr_opts.dsskeyfile = NULL;
	svr_opts.bannerfile = NULL;
	svr_opts.banner = NULL;
	svr_opts.forkbg = 1;
	svr_opts.norootlogin = 0;
	svr_opts.noauthpass = 0;
	svr_opts.norootpass = 0;
	opts.nolocaltcp = 0;
	opts.noremotetcp = 0;
	/* not yet
	opts.ipv4 = 1;
	opts.ipv6 = 1;
	*/
#ifdef DO_MOTD
	svr_opts.domotd = 1;
#endif
#ifndef DISABLE_SYSLOG
	svr_opts.usingsyslog = 1;
#endif

	for (i = 1; i < (unsigned int)argc; i++) {
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
					next = &svr_opts.bannerfile;
					break;
#ifdef DROPBEAR_DSS
				case 'd':
					next = &svr_opts.dsskeyfile;
					break;
#endif
#ifdef DROPBEAR_RSA
				case 'r':
					next = &svr_opts.rsakeyfile;
					break;
#endif
				case 'F':
					svr_opts.forkbg = 0;
					break;
#ifndef DISABLE_SYSLOG
				case 'E':
					svr_opts.usingsyslog = 0;
					break;
#endif
#ifndef DISABLE_LOCALTCPFWD
				case 'j':
					opts.nolocaltcp = 1;
					break;
#endif
#ifndef DISABLE_REMOTETCPFWD
				case 'k':
					opts.noremotetcp = 1;
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
					svr_opts.domotd = 0;
					break;
#endif
				case 'w':
					svr_opts.norootlogin = 1;
					break;
#ifdef ENABLE_SVR_PASSWORD_AUTH
				case 's':
					svr_opts.noauthpass = 1;
					break;
				case 'g':
					svr_opts.norootpass = 1;
					break;
#endif
				case 'h':
					printhelp(argv[0]);
					exit(EXIT_FAILURE);
					break;
					/*
				case '4':
					svr_opts.ipv4 = 0;
					break;
				case '6':
					svr_opts.ipv6 = 0;
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

	if (svr_opts.dsskeyfile == NULL) {
		svr_opts.dsskeyfile = DSS_PRIV_FILENAME;
	}
	if (svr_opts.rsakeyfile == NULL) {
		svr_opts.rsakeyfile = RSA_PRIV_FILENAME;
	}
	svr_opts.hostkey = loadhostkeys(svr_opts.dsskeyfile, svr_opts.rsakeyfile);

	if (svr_opts.bannerfile) {
		struct stat buf;
		if (stat(svr_opts.bannerfile, &buf) != 0) {
			dropbear_exit("Error opening banner file '%s'",
					svr_opts.bannerfile);
		}
		
		if (buf.st_size > MAX_BANNER_SIZE) {
			dropbear_exit("Banner file too large, max is %d bytes",
					MAX_BANNER_SIZE);
		}

		svr_opts.banner = buf_new(buf.st_size);
		if (buf_readfile(svr_opts.banner, svr_opts.bannerfile)!=DROPBEAR_SUCCESS) {
			dropbear_exit("Error reading banner file '%s'",
					svr_opts.bannerfile);
		}
		buf_setpos(svr_opts.banner, 0);
	}

	/* not yet
	if (!(svr_opts.ipv4 || svr_opts.ipv6)) {
		fprintf(stderr, "You can't disable ipv4 and ipv6.\n");
		exit(1);
	}
	*/

	/* create the array of listening ports */
	if (portnum == 0) {
		/* non specified */
		svr_opts.portcount = 1;
		svr_opts.ports = m_malloc(sizeof(uint16_t));
		svr_opts.ports[0] = DROPBEAR_PORT;
	} else {
		svr_opts.portcount = portnum;
		svr_opts.ports = (uint16_t*)m_malloc(sizeof(uint16_t)*portnum);
		for (i = 0; i < portnum; i++) {
			if (portstring[i]) {
				longport = atoi(portstring[i]);
					if (longport <= 65535 && longport > 0) {
						svr_opts.ports[i] = (uint16_t)longport;
						continue;
					}
			}
			fprintf(stderr, "Bad port '%s'\n",
					portstring[i] ? portstring[i] : "null");
		}
	}

}

static void disablekey(int type, const char* filename) {

	int i;

	for (i = 0; sshhostkey[i].name != NULL; i++) {
		if (sshhostkey[i].val == type) {
			sshhostkey[i].usable = 0;
			break;
		}
	}
	fprintf(stderr, "Failed reading '%s', disabling %s\n", filename,
			type == DROPBEAR_SIGNKEY_DSS ? "DSS" : "RSA");
}

static sign_key * loadhostkeys(const char * dsskeyfile, 
		const char * rsakeyfile) {

	sign_key * hostkey;
	int ret;
	int type;

	TRACE(("enter loadhostkeys"));

	hostkey = new_sign_key();

#ifdef DROPBEAR_RSA
	type = DROPBEAR_SIGNKEY_RSA;
	ret = readhostkey(rsakeyfile, hostkey, &type);
	if (ret == DROPBEAR_FAILURE) {
		disablekey(DROPBEAR_SIGNKEY_RSA, rsakeyfile);
	}
#endif
#ifdef DROPBEAR_DSS
	type = DROPBEAR_SIGNKEY_RSA;
	ret = readhostkey(dsskeyfile, hostkey, &type);
	if (ret == DROPBEAR_FAILURE) {
		disablekey(DROPBEAR_SIGNKEY_DSS, dsskeyfile);
	}
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
