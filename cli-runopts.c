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

	unsigned int i, j;
	char ** next = 0;
	unsigned int cmdlen;
	int nextiskey = 0; /* A flag if the next argument is a keyfile */

	uid_t uid;
	struct passwd *pw = NULL; 

	char* userhostarg = NULL;

	/* see printhelp() for options */
	cli_opts.progname = argv[0];
	cli_opts.remotehost = NULL;
	cli_opts.remoteport = NULL;
	cli_opts.username = NULL;
	cli_opts.cmd = NULL;
	cli_opts.wantpty = 1;
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

	for (i = 1; i < (unsigned int)argc; i++) {
		if (nextiskey) {
			/* XXX do stuff */
			break;
		}
		if (next) {
			*next = argv[i];
			if (*next == NULL) {
				dropbear_exit("Invalid null argument");
			}
			next = NULL;
			continue;
		}

		if (argv[i][0] == '-') {

			/* A flag *waves* */
			switch (argv[i][1]) {
				case 'p':
					next = &cli_opts.remoteport;
					break;
#ifdef DROPBEAR_PUBKEY_AUTH
				case 'i':
					nextiskey = 1;
					break;
#endif
				default:
					fprintf(stderr, "Unknown argument %s\n", argv[i]);
					printhelp(argv[0]);
					exit(EXIT_FAILURE);
					break;
			} /* Switch */

		} else {

			/* Either the hostname or commands */
			/* Hostname is first up, must be set before we get the cmds */

			if (cli_opts.remotehost == NULL) {
				/* We'll be editing it, should probably make a copy */
				userhostarg = m_strdup(argv[1]);

				cli_opts.remotehost = strchr(userhostarg, '@');
				if (cli_opts.remotehost == NULL) {
					/* no username portion, the cli-auth.c code can figure the
					 * local user's name */
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
						dropbear_exit("I don't know my own [user]name");
					}

					cli_opts.username = m_strdup(pw->pw_name);
				}

				if (cli_opts.remotehost[0] == '\0') {
					dropbear_exit("Bad hostname");
				}
			} else {
				/* this is part of the commands to send - after this we
				 * don't parse any more options, and flags are sent as the
				 * command */
				cmdlen = 0;
				for (j = i; j < (unsigned int)argc; j++) {
					cmdlen += strlen(argv[j]) + 1; /* +1 for spaces */
				}
				/* Allocate the space */
				cli_opts.cmd = (char*)m_malloc(cmdlen);
				cli_opts.cmd[0] = '\0';

				/* Append all the bits */
				for (j = i; j < (unsigned int)argc; j++) {
					strlcat(cli_opts.cmd, argv[j], cmdlen);
					strlcat(cli_opts.cmd, " ", cmdlen);
				}
				/* It'll be null-terminated here */

				/* We've eaten all the options and flags */
				break;
			}
		}
	}
}
