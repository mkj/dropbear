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

static void printhelp();
static void parsehostname(char* userhostarg);
#ifdef DROPBEAR_PUBKEY_AUTH
static void loadidentityfile(const char* filename);
#endif

static void printhelp() {

	fprintf(stderr, "Dropbear client v%s\n"
					"Usage: %s [options] user@host\n"
					"Options are:\n"
					"-p <remoteport>\n"
					"-t    Allocate a pty\n"
					"-T    Don't allocate a pty\n"
#ifdef DROPBEAR_PUBKEY_AUTH
					"-i <identityfile>   (multiple allowed)\n"
#endif
					,DROPBEAR_VERSION, cli_opts.progname);
}

void cli_getopts(int argc, char ** argv) {

	unsigned int i, j;
	char ** next = 0;
	unsigned int cmdlen;
#ifdef DROPBEAR_PUBKEY_AUTH
	int nextiskey = 0; /* A flag if the next argument is a keyfile */
#endif



	/* see printhelp() for options */
	cli_opts.progname = argv[0];
	cli_opts.remotehost = NULL;
	cli_opts.remoteport = NULL;
	cli_opts.username = NULL;
	cli_opts.cmd = NULL;
	cli_opts.wantpty = 9; /* 9 means "it hasn't been touched", gets set later */
#ifdef DROPBEAR_PUBKEY_AUTH
	cli_opts.pubkeys = NULL;
#endif
	opts.nolocaltcp = 0;
	opts.noremotetcp = 0;
	/* not yet
	opts.ipv4 = 1;
	opts.ipv6 = 1;
	*/

	/* Iterate all the arguments */
	for (i = 1; i < (unsigned int)argc; i++) {
#ifdef DROPBEAR_PUBKEY_AUTH
		if (nextiskey) {
			/* Load a hostkey since the previous argument was "-i" */
			loadidentityfile(argv[i]);
			nextiskey = 0;
			continue;
		}
#endif
		if (next) {
			/* The previous flag set a value to assign */
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
				case 'p': /* remoteport */
					next = &cli_opts.remoteport;
					break;
#ifdef DROPBEAR_PUBKEY_AUTH
				case 'i': /* an identityfile */
					nextiskey = 1;
					break;
#endif
				case 't': /* we want a pty */
					cli_opts.wantpty = 1;
					break;
				case 'T': /* don't want a pty */
					cli_opts.wantpty = 0;
					break;
				default:
					fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
					printhelp();
					exit(EXIT_FAILURE);
					break;
			} /* Switch */

			continue; /* next argument */

		} else {
			TRACE(("non-flag arg"));

			/* Either the hostname or commands */

			if (cli_opts.remotehost == NULL) {

				parsehostname(argv[i]);

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

	if (cli_opts.remotehost == NULL) {
		dropbear_exit("Bad syntax");
	}

	if (cli_opts.remoteport == NULL) {
		cli_opts.remoteport = "22";
	}

	/* If not explicitly specified with -t or -T, we don't want a pty if
	 * there's a command, but we do otherwise */
	if (cli_opts.wantpty == 9) {
		if (cli_opts.cmd == NULL) {
			cli_opts.wantpty = 1;
		} else {
			cli_opts.wantpty = 0;
		}
	}
}

#ifdef DROPBEAR_PUBKEY_AUTH
static void loadidentityfile(const char* filename) {

	struct PubkeyList * nextkey;
	sign_key *key;
	int keytype;

	key = new_sign_key();
	keytype = DROPBEAR_SIGNKEY_ANY;
	if ( readhostkey(filename, key, &keytype) != DROPBEAR_SUCCESS ) {

		fprintf(stderr, "Failed loading keyfile '%s'\n", filename);
		sign_key_free(key);

	} else {

		nextkey = (struct PubkeyList*)m_malloc(sizeof(struct PubkeyList));
		nextkey->key = key;
		nextkey->next = cli_opts.pubkeys;
		nextkey->type = keytype;
		cli_opts.pubkeys = nextkey;
	}
}
#endif


/* Parses a [user@]hostname argument. userhostarg is the argv[i] corresponding
 * - note that it will be modified */
static void parsehostname(char* userhostarg) {

	uid_t uid;
	struct passwd *pw = NULL; 

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
			dropbear_exit("Unknown own user");
		}

		cli_opts.username = m_strdup(pw->pw_name);
	}

	if (cli_opts.remotehost[0] == '\0') {
		dropbear_exit("Bad hostname");
	}
}
