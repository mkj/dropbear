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

cli_runopts cli_opts; /* GLOBAL */

static void printhelp(const char * progname);

static void printhelp(const char * progname) {

	fprintf(stderr, "Dropbear client v%s\n"
					"Usage: %s [options] user@host[:port]\n"
					"Options are:\n"
					"user		Remote username\n"
					"host		Remote host\n"
					"port		Remote port\n"
					,DROPBEAR_VERSION, progname);
}

void cli_getopts(int argc, char ** argv) {

	unsigned int i;
	char ** next = 0;

	uid_t uid;
	struct passwd *pw; 

	char* userhostarg = NULL;

	/* see printhelp() for options */
	cli_opts.remotehost = NULL;
	cli_opts.remoteport = NULL;
	cli_opts.username = NULL;
	cli_opts.cmd = NULL;
	cli_opts.wantpty = 0;
	opts.nolocaltcp = 0;
	opts.noremotetcp = 0;
	/* not yet
	opts.ipv4 = 1;
	opts.ipv6 = 1;
	*/

	if (argc != 2) {
		printhelp(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* We'll be editing it, should probably make a copy */
	userhostarg = m_strdup(argv[1]);

	cli_opts.remotehost = strchr(userhostarg, '@');
	if (cli_opts.remotehost == NULL) {
		/* no username portion, the cli-auth.c code can figure the local
		 * user's name */
		cli_opts.remotehost = userhostarg;
	} else {
		cli_opts.remotehost[0] = '\0'; /* Split the user/host */
		cli_opts.remotehost++;
		cli_opts.username = userhostarg;
	}

	if (cli_opts.username == NULL) {
		uid = getuid();
		
		pw = getpwuid(uid);
		if (pw == NULL || pw->pw_name == NULL) {
			dropbear_exit("Couldn't find username for current user");
		}

		cli_opts.username = m_strdup(pw->pw_name);
	}

	if (cli_opts.remotehost[0] == '\0') {
		dropbear_exit("Bad hostname argument");
	}

	cli_opts.remoteport = strchr(cli_opts.remotehost, ':');
	if (cli_opts.remoteport == NULL) {
		cli_opts.remoteport = "22";
	} else {
		cli_opts.remoteport[0] = '\0';
		cli_opts.remoteport++;
	}

#if 0
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
#ifdef DROPBEAR_PASSWORD_AUTH
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
#endif

}
