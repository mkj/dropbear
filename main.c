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
 * furnished to do so, subject to the following condition:
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "options.h"
#include "util.h"
#include "session.h"
#include "buffer.h"
#include "signkey.h"
#include "runopts.h"

static void listensocket(int *sock, uint16_t port);
static void sigchld_handler(int dummy);
static void sigsegv_handler(int);

static int childpipes[MAX_UNAUTH_CLIENTS];

int main(int argc, char ** argv) {
	
	fd_set fds;
	struct timeval seltimeout;
	int i, j, val;
	int maxsock;
	struct sockaddr remote_addr;
	int remote_addrlen;
	int listensocks[MAX_LISTEN_ADDR];
	unsigned int listensockcount = 0;
	runopts * opts;

	int childsock;
	pid_t childpid;
	int childpipe[2];

	struct sigaction sa_chld;

	/* get commandline options */
	opts = getrunopts(argc, argv);


	/* fork to background, returning (interactive) users to a term */
	if (opts->forkbg) {

		switch (fork()) {
			case -1:
				dropbear_exit("Failed to create background process");
			case 0:
				break;
			default:
				exit(0);
		}
		if (setpgid(0,0) < 0) {
			dropbear_exit("Failed to set process group");
		}
		startsyslog();
		fprintf(stderr,"Dropbear: Running in background.\n");
	} else {
		fprintf(stderr,"Dropbear: Not forking\n");
	}
	
	/* setup the sockets - we're allowing for multiple listening sockets
	 * so we can do ip6 etc in future */
	listensocket(&listensocks[0], opts->port);
	listensockcount = 1;
	maxsock = listensocks[listensockcount-1];

	/* catch and reap zombie children */
	
	sa_chld.sa_handler = sigchld_handler;
	sa_chld.sa_flags = SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa_chld, NULL) < 0) {
		dropbear_exit("signal() error");
	}
	if (signal(SIGSEGV, sigsegv_handler) == SIG_ERR) {
		dropbear_exit("signal() error");
	}

	/* sockets to identify pre-authenticated clients */
	for (i = 0; i < MAX_UNAUTH_CLIENTS; i++) {
		childpipes[i] = -1;
	}

	/* incoming connection select loop */
	for(;;) {

		FD_ZERO(&fds);
		
		seltimeout.tv_sec = 60; /* TODO find good value */
		seltimeout.tv_usec = 0;
		
		/* listening sockets */
		for (i = 0; i < listensockcount; i++) {
			FD_SET(listensocks[i], &fds);
		}

		/* pre-authentication clients */
		for (i = 0; i < MAX_UNAUTH_CLIENTS; i++) {
			if (childpipes[i] >= 0) 
			FD_SET(childpipes[i], &fds);
			maxsock = MAX(maxsock, childpipes[i]);
		}

		val = select(maxsock+1, &fds, NULL, NULL, &seltimeout);
		if (val == 0) {
			/* timeout reached */
			continue;
		}
		if (val < 0) {
			if (errno == EINTR) {
				continue;
			}
			dropbear_exit("Listening socket error");
		}

		/* close fds which have been authed or closed */
		for (i = 0; i < MAX_UNAUTH_CLIENTS; i++) {
			if (childpipes[i] >= 0 && FD_ISSET(childpipes[i], &fds)) {
				close(childpipes[i]);
				childpipes[i] = -1;
			}
		}

		/* handle each socket which has something to say */
		for (i = 0; i < listensockcount; i++) {
			if (!FD_ISSET(listensocks[i], &fds)) 
				continue;

			/* child connection */
			remote_addrlen = sizeof(struct sockaddr_in);
			childsock = accept(listensocks[i], 
					&remote_addr, &remote_addrlen);

			if (childsock < 0) {
				/* accept failed */
				continue;
			}

			/* check for max number of connections not authorised */
			for (j = 0; j < MAX_UNAUTH_CLIENTS; j++) {
				if (childpipes[j] < 0) {
					break;
				}
			}
			if (j == MAX_UNAUTH_CLIENTS) {
				/* no free connections */
				/* TODO - possibly log, though this would be an easy way
				 * to fill logs/disk */
				close(childsock);
				continue;
			}

			if (pipe(childpipe) < 0) {
				TRACE(("error creating child pipe"));
				close(childsock);
				continue;
			}

			if ((childpid = fork()) == 0) {

				/* child */
				if (setpgid(0,0) < 0) {
					dropbear_exit("Error creating child");
				}

				/* make sure we close sockets */
				for (i = 0; i < listensockcount; i++) {
					if (m_close(listensocks[i]) == -1) {
						dropbear_exit("Couldn't close socket");
					}
				}

				if (m_close(childpipe[0]) == -1) {
					dropbear_exit("Couldn't close socket");
				}
				/* start the session */
				child_session(childsock, opts, childpipe[1], &remote_addr);
				/* don't return */
				assert(0);
			}
			
			/* parent */
			childpipes[j] = childpipe[0];
			if (m_close(childpipe[1]) == -1
						|| m_close(childsock) == -1) {
				dropbear_exit("Couldn't close socket");
			}
		}
	} /* for(;;) loop */

	/* don't reach here */
	return -1;
}

/* catch + reap zombie children */
static void sigchld_handler(int fish) {
	struct sigaction sa_chld;

	while(waitpid(-1, NULL, WNOHANG) > 0); 

	sa_chld.sa_handler = sigchld_handler;
	sa_chld.sa_flags = SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa_chld, NULL) < 0) {
		dropbear_exit("signal() error");
	}
}

/* catch any segvs */
static void sigsegv_handler(int fish) {
	fprintf(stderr, "Aiee, segfault! You should probably report "
			"this as a bug to the developer\n");
	exit(EXIT_FAILURE);
}

static void listensocket(int *sock, uint16_t port) {
	
	int listensock; /* listening fd */
	struct sockaddr_in listen_addr;
	struct linger linger;
	int val;

	/* open a socket */
	listensock = socket(PF_INET, SOCK_STREAM, 0);
	if (listensock < 0) {
		dropbear_exit("Failed to create socket");
	}

	/* set to reuse, quick timeout */
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR,
			(void*) &val, sizeof(val));
	linger.l_onoff = 1;
	linger.l_linger = 5;
	setsockopt(listensock, SOL_SOCKET, SO_LINGER,
			(void*)&linger, sizeof(linger));

	val = 1;
	/* should really use getprotbyname, but we'd need to change "tcp" anyway */
	setsockopt(listensock, 6, TCP_NODELAY, (void*)&val, sizeof(val));

	/* bind all ip4 addresses */
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_port = htons(port);
	listen_addr.sin_addr.s_addr = INADDR_ANY;
	memset(&(listen_addr.sin_zero), '\0', 8); /* XXX neccesary? */

	if (bind(listensock, (struct sockaddr *)&listen_addr, 
				sizeof(struct sockaddr)) < 0) {
		dropbear_exit("Bind failed");
	}

	/* listen */
	if (listen(listensock, 20) < 0) { /* TODO set listen count */
		dropbear_exit("Listen failed");
	}

	/* nonblock */
	if (fcntl(listensock, F_SETFL, O_NONBLOCK) < 0) {
		dropbear_exit("Failed to set non-blocking");
	}

	*sock = listensock;
}
