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

#ifndef DISABLE_X11FWD
#include "x11fwd.h"
#include "session.h"
#include "ssh.h"
#include "dbutil.h"
#include "chansession.h"
#include "channel.h"
#include "packet.h"
#include "buffer.h"

#define X11BASEPORT 6000
#define X11BINDBASE 6010

static int bindport(int fd);
static int send_msg_channel_open_x11(int fd, struct sockaddr_in* addr);

/* called as a request for a session channel, sets up listening X11 */
/* returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int x11req(struct ChanSess * chansess) {

	/* we already have an x11 connection */
	if (chansess->x11fd != -1) {
		return DROPBEAR_FAILURE;
	}

	chansess->x11singleconn = buf_getbyte(ses.payload);
	chansess->x11authprot = buf_getstring(ses.payload, NULL);
	chansess->x11authcookie = buf_getstring(ses.payload, NULL);
	chansess->x11screennum = buf_getint(ses.payload);

	/* create listening socket */
	chansess->x11fd = socket(PF_INET, SOCK_STREAM, 0);
	if (chansess->x11fd < 0) {
		goto fail;
	}

	/* allocate port and bind */
	chansess->x11port = bindport(chansess->x11fd);
	if (chansess->x11port < 0) {
		goto fail;
	}

	/* listen */
	if (listen(chansess->x11fd, 20) < 0) {
		goto fail;
	}

	/* set non-blocking */
	if (fcntl(chansess->x11fd, F_SETFL, O_NONBLOCK) < 0) {
		goto fail;
	}

	/* channel.c's channel fd code will handle the socket now */

	/* set the maxfd so that select() loop will notice it */
	ses.maxfd = MAX(ses.maxfd, chansess->x11fd);

	return DROPBEAR_SUCCESS;

fail:
	/* cleanup */
	x11cleanup(chansess);

	return DROPBEAR_FAILURE;
}

/* accepts a new X11 socket */
/* returns DROPBEAR_FAILURE or DROPBEAR_SUCCESS */
int x11accept(struct ChanSess * chansess) {

	int fd;
	struct sockaddr_in addr;
	int len;

	len = sizeof(addr);

	fd = accept(chansess->x11fd, (struct sockaddr*)&addr, &len);
	if (fd < 0) {
		return DROPBEAR_FAILURE;
	}

	/* if single-connection we close it up */
	if (chansess->x11singleconn) {
		x11cleanup(chansess);
	}

	return send_msg_channel_open_x11(fd, &addr);
}

/* This is called after switching to the user, and sets up the xauth
 * and environment variables.  */
void x11setauth(struct ChanSess *chansess) {

	char display[20]; /* space for "localhost:12345.123" */
	FILE * authprog;
	int val;

	if (chansess->x11fd == -1) {
		return;
	}

	/* create the DISPLAY string */
	val = snprintf(display, sizeof(display), "localhost:%d.%d",
			chansess->x11port - X11BASEPORT, chansess->x11screennum);
	if (val < 0 || val >= (int)sizeof(display)) {
		/* string was truncated */
		return;
	}

	addnewvar("DISPLAY", display);

	/* create the xauth string */
	val = snprintf(display, sizeof(display), "unix:%d.%d",
			chansess->x11port - X11BASEPORT, chansess->x11screennum);
	if (val < 0 || val >= (int)sizeof(display)) {
		/* string was truncated */
		return;
	}

	/* popen is a nice function - code is strongly based on OpenSSH's */
	authprog = popen(XAUTH_COMMAND, "w");
	if (authprog) {
		fprintf(authprog, "add %s %s %s\n",
				display, chansess->x11authprot, chansess->x11authcookie);
		pclose(authprog);
	} else {
		fprintf(stderr, "Failed to run %s\n", XAUTH_COMMAND);
	}
}

void x11cleanup(struct ChanSess * chansess) {

	if (chansess->x11fd == -1) {
		return;
	}

	m_free(chansess->x11authprot);
	m_free(chansess->x11authcookie);
	close(chansess->x11fd);
	chansess->x11fd = -1;
}

static int send_msg_channel_open_x11(int fd, struct sockaddr_in* addr) {

	char* ipstring;

	if (send_msg_channel_open_init(fd, "x11") == DROPBEAR_SUCCESS) {
		ipstring = inet_ntoa(addr->sin_addr);
		buf_putstring(ses.writepayload, ipstring, strlen(ipstring));
		buf_putint(ses.writepayload, addr->sin_port);

		encrypt_packet();
		return DROPBEAR_SUCCESS;
	} else {
		return DROPBEAR_FAILURE;
	}

}

/* returns the port bound to, or -1 on failure.
 * Will attempt to bind to a port X11BINDBASE (6010 usually) or upwards */
static int bindport(int fd) {

	struct sockaddr_in addr;
	uint16_t port;

	memset((void*)&addr, 0x0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	/* if we can't find one in 2000 ports free, something's wrong */
	for (port = X11BINDBASE; port < X11BINDBASE + 2000; port++) {
		addr.sin_port = htons(port);
		if (bind(fd, (struct sockaddr*)&addr, 
					sizeof(struct sockaddr_in)) == 0) {
			/* success */
			return port;
		}
		if (errno == EADDRINUSE) {
			/* try the next port */
			continue;
		}
		/* otherwise it was an error we don't know about */
		dropbear_log(LOG_DEBUG, "failed to bind x11 socket");
		break;
	}
	return -1;
}
#endif /* DROPBEAR_X11FWD */
