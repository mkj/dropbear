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
#include "tcpfwd.h"

cli_runopts cli_opts; /* GLOBAL */

static void printhelp();
static void parsehostname(char* userhostarg);
#ifdef ENABLE_CLI_PUBKEY_AUTH
static void loadidentityfile(const char* filename);
#endif
#ifdef ENABLE_CLI_ANYTCPFWD
static void addforward(char* str, struct TCPFwdList** fwdlist);
#endif

static void printhelp() {

	fprintf(stderr, "Dropbear client v%s\n"
					"Usage: %s [options] [user@]host [command]\n"
					"Options are:\n"
					"-p <remoteport>\n"
					"-l <username>\n"
					"-t    Allocate a pty\n"
					"-T    Don't allocate a pty\n"
					"-N    Don't run a remote command\n"
					"-f    Run in background after auth\n"
					"-y    Always accept remote host key if unknown\n"
#ifdef ENABLE_CLI_PUBKEY_AUTH
					"-i <identityfile>   (multiple allowed)\n"
#endif
#ifdef ENABLE_CLI_LOCALTCPFWD
					"-L <listenport:remotehost:remoteport> Local port forwarding\n"
					"-g    Allow remote hosts to connect to forwarded ports\n"
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
					"-R <listenport:remotehost:remoteport> Remote port forwarding\n"
#endif
					"-W <receive_window_buffer> (default %d, larger may be faster, max 1MB)\n"
					"-K <keepalive>  (0 is never, default %d)\n"
#ifdef DEBUG_TRACE
					"-v    verbose\n"
#endif
					,DROPBEAR_VERSION, cli_opts.progname,
					DEFAULT_RECV_WINDOW, DEFAULT_KEEPALIVE);
					
}

void cli_getopts(int argc, char ** argv) {

	unsigned int i, j;
	char ** next = 0;
	unsigned int cmdlen;
#ifdef ENABLE_CLI_PUBKEY_AUTH
	int nextiskey = 0; /* A flag if the next argument is a keyfile */
#endif
#ifdef ENABLE_CLI_LOCALTCPFWD
	int nextislocal = 0;
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
	int nextisremote = 0;
#endif
	char* dummy = NULL; /* Not used for anything real */

	/* see printhelp() for options */
	cli_opts.progname = argv[0];
	cli_opts.remotehost = NULL;
	cli_opts.remoteport = NULL;
	cli_opts.username = NULL;
	cli_opts.cmd = NULL;
	cli_opts.no_cmd = 0;
	cli_opts.backgrounded = 0;
	cli_opts.wantpty = 9; /* 9 means "it hasn't been touched", gets set later */
	cli_opts.always_accept_key = 0;
#ifdef ENABLE_CLI_PUBKEY_AUTH
	cli_opts.privkeys = NULL;
#endif
#ifdef ENABLE_CLI_LOCALTCPFWD
	cli_opts.localfwds = NULL;
	opts.listen_fwd_all = 0;
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
	cli_opts.remotefwds = NULL;
#endif
	/* not yet
	opts.ipv4 = 1;
	opts.ipv6 = 1;
	*/
	opts.recv_window = DEFAULT_RECV_WINDOW;
	char* recv_window_arg = NULL;
	char* keepalive_arg = NULL;

	/* Iterate all the arguments */
	for (i = 1; i < (unsigned int)argc; i++) {
#ifdef ENABLE_CLI_PUBKEY_AUTH
		if (nextiskey) {
			/* Load a hostkey since the previous argument was "-i" */
			loadidentityfile(argv[i]);
			nextiskey = 0;
			continue;
		}
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
		if (nextisremote) {
			TRACE(("nextisremote true"))
			addforward(argv[i], &cli_opts.remotefwds);
			nextisremote = 0;
			continue;
		}
#endif
#ifdef ENABLE_CLI_LOCALTCPFWD
		if (nextislocal) {
			TRACE(("nextislocal true"))
			addforward(argv[i], &cli_opts.localfwds);
			nextislocal = 0;
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
				case 'y': /* always accept the remote hostkey */
					cli_opts.always_accept_key = 1;
					break;
				case 'p': /* remoteport */
					next = &cli_opts.remoteport;
					break;
#ifdef ENABLE_CLI_PUBKEY_AUTH
				case 'i': /* an identityfile */
					/* Keep scp happy when it changes "-i file" to "-ifile" */
					if (strlen(argv[i]) > 2) {
						loadidentityfile(&argv[i][2]);
					} else  {
						nextiskey = 1;
					}
					break;
#endif
				case 't': /* we want a pty */
					cli_opts.wantpty = 1;
					break;
				case 'T': /* don't want a pty */
					cli_opts.wantpty = 0;
					break;
				case 'N':
					cli_opts.no_cmd = 1;
					break;
				case 'f':
					cli_opts.backgrounded = 1;
					break;
#ifdef ENABLE_CLI_LOCALTCPFWD
				case 'L':
					nextislocal = 1;
					break;
				case 'g':
					opts.listen_fwd_all = 1;
					break;
#endif
#ifdef ENABLE_CLI_REMOTETCPFWD
				case 'R':
					nextisremote = 1;
					break;
#endif
				case 'l':
					next = &cli_opts.username;
					break;
				case 'h':
					printhelp();
					exit(EXIT_SUCCESS);
					break;
				case 'u':
					/* backwards compatibility with old urandom option */
					break;
				case 'W':
					next = &recv_window_arg;
					break;
				case 'K':
					next = &keepalive_arg;
					break;
#ifdef DEBUG_TRACE
				case 'v':
					debug_trace = 1;
					break;
#endif
				case 'F':
				case 'e':
				case 'c':
				case 'm':
				case 'D':
#ifndef ENABLE_CLI_REMOTETCPFWD
				case 'R':
#endif
#ifndef ENABLE_CLI_LOCALTCPFWD
				case 'L':
#endif
				case 'o':
				case 'b':
					next = &dummy;
				default:
					fprintf(stderr, 
						"WARNING: Ignoring unknown argument '%s'\n", argv[i]);
					break;
			} /* Switch */
			
			/* Now we handle args where they might be "-luser" (no spaces)*/
			if (next && strlen(argv[i]) > 2) {
				*next = &argv[i][2];
				next = NULL;
			}

			continue; /* next argument */

		} else {
			TRACE(("non-flag arg: '%s'", argv[i]))

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
		printhelp();
		exit(EXIT_FAILURE);
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

	if (cli_opts.backgrounded && cli_opts.cmd == NULL
			&& cli_opts.no_cmd == 0) {
		dropbear_exit("command required for -f");
	}
	
	if (recv_window_arg)
	{
		opts.recv_window = atol(recv_window_arg);
		if (opts.recv_window == 0 || opts.recv_window > MAX_RECV_WINDOW)
		{
			dropbear_exit("Bad recv window '%s'", recv_window_arg);
		}
	}
	if (keepalive_arg) {
		opts.keepalive_secs = strtoul(keepalive_arg, NULL, 10);
		if (opts.keepalive_secs == 0 && errno == EINVAL)
		{
			dropbear_exit("Bad keepalive '%s'", keepalive_arg);
		}
	}
	
}

#ifdef ENABLE_CLI_PUBKEY_AUTH
static void loadidentityfile(const char* filename) {

	struct SignKeyList * nextkey;
	sign_key *key;
	int keytype;

	key = new_sign_key();
	keytype = DROPBEAR_SIGNKEY_ANY;
	if ( readhostkey(filename, key, &keytype) != DROPBEAR_SUCCESS ) {

		fprintf(stderr, "Failed loading keyfile '%s'\n", filename);
		sign_key_free(key);

	} else {

		nextkey = (struct SignKeyList*)m_malloc(sizeof(struct SignKeyList));
		nextkey->key = key;
		nextkey->next = cli_opts.privkeys;
		nextkey->type = keytype;
		cli_opts.privkeys = nextkey;
	}
}
#endif


/* Parses a [user@]hostname argument. userhostarg is the argv[i] corresponding
 * - note that it will be modified */
static void parsehostname(char* orighostarg) {

	uid_t uid;
	struct passwd *pw = NULL; 
	char *userhostarg = NULL;

	/* We probably don't want to be editing argvs */
	userhostarg = m_strdup(orighostarg);

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

#ifdef ENABLE_CLI_ANYTCPFWD
/* Turn a "listenport:remoteaddr:remoteport" string into into a forwarding
 * set, and add it to the forwarding list */
static void addforward(char* origstr, struct TCPFwdList** fwdlist) {

	char * listenport = NULL;
	char * connectport = NULL;
	char * connectaddr = NULL;
	struct TCPFwdList* newfwd = NULL;
	char * str = NULL;

	TRACE(("enter addforward"))

	/* We need to split the original argument up. This var
	   is never free()d. */ 
	str = m_strdup(origstr);

	listenport = str;

	connectaddr = strchr(str, ':');
	if (connectaddr == NULL) {
		TRACE(("connectaddr == NULL"))
		goto fail;
	}
	*connectaddr = '\0';
	connectaddr++;

	connectport = strchr(connectaddr, ':');
	if (connectport == NULL) {
		TRACE(("connectport == NULL"))
		goto fail;
	}
	*connectport = '\0';
	connectport++;

	newfwd = (struct TCPFwdList*)m_malloc(sizeof(struct TCPFwdList));

	/* Now we check the ports - note that the port ints are unsigned,
	 * the check later only checks for >= MAX_PORT */
	newfwd->listenport = strtol(listenport, NULL, 10);
	if (errno != 0) {
		TRACE(("bad listenport strtol"))
		goto fail;
	}

	newfwd->connectport = strtol(connectport, NULL, 10);
	if (errno != 0) {
		TRACE(("bad connectport strtol"))
		goto fail;
	}

	newfwd->connectaddr = connectaddr;

	if (newfwd->listenport > 65535) {
		TRACE(("listenport > 65535"))
		goto badport;
	}
		
	if (newfwd->connectport > 65535) {
		TRACE(("connectport > 65535"))
		goto badport;
	}

	newfwd->next = *fwdlist;
	*fwdlist = newfwd;

	TRACE(("leave addforward: done"))
	return;

fail:
	dropbear_exit("Bad TCP forward '%s'", origstr);

badport:
	dropbear_exit("Bad TCP port in '%s'", origstr);
}
#endif
