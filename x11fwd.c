#include "options.h"
#include "chansession.h"
#include "channel.h"

#ifndef DISABLE_X11FWD

static int bindport(int fd);

/* called as a request for a session channel, sets up listening X11 */
/* returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int x11req(struct Chansess * chansess) {

	/* we already have an x11 connection */
	if (chansess->x11fd != -1) {
		return DROPBEAR_FAILURE;
	}

	chansess->singleconn = buf_getint(ses.payload);
	chansess->authprot = buf_getstring(ses.payload, NULL);
	chansess->authcookie = buf_getstring(ses.payload, NULL);
	chansess->screennum = buf_getint(ses.payload);

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
	if (fnctl(chansess->x11fd, F_SETFL, O_NONBLOCK) < 0) {
		goto fail;
	}

	/* channel.c's channel fd code will handle the socket now */

	return DROPBEAR_SUCCESS;

fail:
	/* cleanup */
	m_free(chansess->authprot);
	m_free(chansess->authcookie);
	close(chansess->x11fd);
	chansess->x11fd = -1;

	return DROPBEAR_FAILURE;
}

/* accepts a new X11 socket */
/* returns DROPBEAR_FAILURE or DROPBEAR_SUCCESS */
int x11accepter(int sock) {

	int fd;
	struct sockaddr_in addr;

	fd = accept(sock, &addr, sizeof(addr));
	if (fd < 0) {
		return DROPBEAR_FAILURE;
	}

	send_msg_channel_open_x11(fd, addr);

	/* if single-connection we close it up */
}

/* This is called after switching to the user, and sets up the xauth
 * and environment variables. On success it returns the var
 * to set for DISPLAY, or NULL on failure */
void x11setauth(struct ChanSess *chansess) {

	char display[18]; /* space for "127.0.0.1:9999.99" */
	FILE * authprog;

	if (chansess->x11fd == -1) {
		return;
	}

	snprintf(display, sizeof(display), "127.0.0.1:%.4d%.2d",
			chansess->x11port, chansess->x11screennum);

	addnewvar("DISPLAY", display);

	/* popen is a nice function - code is strongly based on OpenSSH's */
	authprog = popen(XAUTH_PROGRAM, "w");
	if (authprog) {
		fprintf(authprog, "add %s %s %s\n",
				display, chansess->x11authprot, chansess->x11authcookie);
		fclose(authprog);
	} else {
		fprintf(stderr, "Failed to run %s\n", XAUTH_PROGRAM);
	}

}


static int send_msg_channel_open_x11(struct sockaddr_in* addr) {

	struct Channel* chan;
	char* ipstring;

	chan = newchannel(-1, CHANNEL_ID_X11, -1, -1);
	if (!chan) {
		return DROPBEAR_FAILURE;
	}

	ipstring = inet_ntoa(addr->sin_addr);

	/* now open the channel connection */
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN);
	buf_putstring(ses.writepayload, "x11");
	buf_putint(ses.writepayload, chan->index);
	buf_putint(ses.writepayload, RECV_MAXWINDOW);
	buf_putint(ses.writepayload, RECV_MAXPACKET);
	buf_putstring(ses.writepayload, ipstring, strlen(ipstring));
	buf_putint(ses.writepayload, addr->sin_port);

	encrypt_packet();

	chan->infd = chan->outfd = fd;

	return DROPBEAR_SUCCESS;
}

/* returns the port bound to, or -1 on failure.
 * Will attempt to bind to a port 6000 or upwards */
static int bindport(int fd) {

	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_addr = INADDR_LOOPBACK;

	/* if we can't find one in 2000 ports free, something's wrong */
	for (addr.sin_port = 6000; addr.sin_port < 8000; addr.sin_port++) {
		if (bind(fd, (struct sockaddr*)&addr, 
					sizeof(struct sockaddr_in)) == 0) {
			/* success */
			return addr.sin_port;
		}
		if (errno != EINVAL) {
			/* error we can't handle */
			break;
		}
		/* otherwise we loop and try a higher port */
	}
	return -1;
}
#endif /* DROPBEAR_X11FWD */
