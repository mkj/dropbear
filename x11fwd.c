#include "options.h"
#include "x11fwd.h"
#include "session.h"
#include "ssh.h"
#include "util.h"
#include "chansession.h"
#include "channel.h"
#include "packet.h"
#include "buffer.h"

#ifndef DISABLE_X11FWD

#define X11BASEPORT 6000

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
		dropbear_log(LOG_DEBUG, "x11req fail socket");
		goto fail;
	}

	/* allocate port and bind */
	chansess->x11port = bindport(chansess->x11fd);
	if (chansess->x11port < 0) {
		goto fail;
	}

	/* listen */
	if (listen(chansess->x11fd, 20) < 0) {
		dropbear_log(LOG_DEBUG, "x11req fail listen");
		goto fail;
	}

	/* set non-blocking */
	if (fcntl(chansess->x11fd, F_SETFL, O_NONBLOCK) < 0) {
		dropbear_log(LOG_DEBUG, "x11req fail nonblock");
		goto fail;
	}

	/* channel.c's channel fd code will handle the socket now */
	dropbear_log(LOG_DEBUG, "x11req success");

	/* set the maxfd so that select() loop will notice it */
	ses.maxfd = MAX(ses.maxfd, chansess->x11fd);

	return DROPBEAR_SUCCESS;

fail:
	/* cleanup */
	dropbear_log(LOG_DEBUG, "x11req fail");
	x11cleanup(chansess);

	return DROPBEAR_FAILURE;
}

/* accepts a new X11 socket */
/* returns DROPBEAR_FAILURE or DROPBEAR_SUCCESS */
int x11accept(struct ChanSess * chansess) {

	int fd;
	struct sockaddr_in addr;
	socklen_t len;

	len = sizeof(addr);

	fd = accept(chansess->x11fd, (struct sockaddr*)&addr, &len);
	if (fd < 0) {
		dropbear_log(LOG_DEBUG, "accept x11 failure %s", strerror(errno));
		return DROPBEAR_FAILURE;
	}

	send_msg_channel_open_x11(fd, &addr);

	/* if single-connection we close it up */
	if (chansess->x11singleconn) {
		x11cleanup(chansess);
	}
	dropbear_log(LOG_DEBUG, "accept x11 success %s", strerror(errno));
	return DROPBEAR_SUCCESS;
}

/* This is called after switching to the user, and sets up the xauth
 * and environment variables.  */
void x11setauth(struct ChanSess *chansess) {

	char display[20]; /* space for "127.0.0.1:12345.123" */
	FILE * authprog;

	if (chansess->x11fd == -1) {
		dropbear_log(LOG_DEBUG, "x11setauth fd == -1");
		return;
	}

	/* create the DISPLAY string */
	if (snprintf(display, sizeof(display), "127.0.0.1:%d.%d",
			chansess->x11port - X11BASEPORT, chansess->x11screennum) 
			>= sizeof(display)) {
		/* string was truncated */
		return;
	}

	addnewvar("DISPLAY", display);
	dropbear_log(LOG_DEBUG, "x11setauth DISPLAY = %s", display);

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

	struct Channel* chan;
	char* ipstring;

	chan = newchannel(-1, CHANNEL_ID_X11, -1, -1, 1);
	if (!chan) {
		dropbear_log(LOG_DEBUG, "failed new channel");
		return DROPBEAR_FAILURE;
	}

	ipstring = inet_ntoa(addr->sin_addr);

	/* now open the channel connection */
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN);
	buf_putstring(ses.writepayload, "x11", 3);
	buf_putint(ses.writepayload, chan->index);
	buf_putint(ses.writepayload, RECV_MAXWINDOW);
	buf_putint(ses.writepayload, RECV_MAXPACKET);
	buf_putstring(ses.writepayload, ipstring, strlen(ipstring));
	buf_putint(ses.writepayload, addr->sin_port);

	encrypt_packet();

	chan->infd = chan->outfd = fd;

	ses.maxfd = MAX(ses.maxfd, fd);

	return DROPBEAR_SUCCESS;
}

/* returns the port bound to, or -1 on failure.
 * Will attempt to bind to a port 6000 or upwards */
static int bindport(int fd) {

	struct sockaddr_in addr;
	uint16_t port;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	/* if we can't find one in 2000 ports free, something's wrong */
	for (port = X11BASEPORT; port < X11BASEPORT + 2000; port++) {
		addr.sin_port = htons(port);
		if (bind(fd, (struct sockaddr*)&addr, 
					sizeof(struct sockaddr_in)) == 0) {
			/* success */
			return port;
		}
		dropbear_log(LOG_DEBUG, "bindport error port %d err %d %s", 
				port, errno, strerror(errno));
		if (errno != EADDRINUSE) {
			/* error we can't handle */
			break;
		}
		/* otherwise we loop and try a higher port */
	}
	return -1;
}
#endif /* DROPBEAR_X11FWD */
