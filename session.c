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
#include "session.h"
#include "util.h"
#include "packet.h"
#include "algo.h"
#include "buffer.h"
#include "dss.h"
#include "ssh.h"
#include "random.h"
#include "kex.h"
#include "channel.h"
#include "atomicio.h"

/* need to know if the session struct has been initialised, this way isn't the
 * cleanest, but works OK */
int sessinitdone = 0;

/* this is set when we get SIGINT or SIGTERM, the handler is in main.c */
int exitflag = 0;

static void session_init(int sock, runopts *opts, int childpipe,
		struct sockaddr *remoteaddr);
static void session_identification();
static void checktimeouts();

struct sshsession ses;

void child_session(int sock, runopts *opts, int childpipe,
		struct sockaddr *remoteaddr) {

	fd_set readfd, writefd;
	struct timeval timeout;
	int val;
	
	crypto_init();
	session_init(sock, opts, childpipe, remoteaddr);

	/* exchange identification, version etc */
	session_identification();

	seedrandom();

	/* start off with key exchange */
	send_msg_kexinit();

	FD_ZERO(&readfd);
	FD_ZERO(&writefd);

	/* main loop, select()s for network and other connections */
	for(;;) {

		TRACE(("top of select loop"));
		timeout.tv_sec = SELECT_TIMEOUT;
		timeout.tv_usec = 0;
		FD_ZERO(&writefd);
		FD_ZERO(&readfd);
		assert(ses.payload == NULL);
		FD_SET(ses.sock, &readfd);
		if (!isempty(&ses.writequeue)) {
			FD_SET(ses.sock, &writefd);
		}

		/* set up for channels which require reading/writing */
		if (ses.dataallowed == 1) {
			setchannelfds(&readfd, &writefd);
		}
		val = select(ses.maxfd+1, &readfd, &writefd, NULL, &timeout);
		TRACE(("select val = %d", val));

		if (exitflag) {
			dropbear_exit("Terminated by signal");
		}
		
		if (val < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				dropbear_exit("Error in select");
			}
		}

		checktimeouts();
		
		if (val == 0) {
			/* timeout */
			TRACE(("select timeout"));
			continue;
		}


		if (FD_ISSET(ses.sock, &writefd) && !isempty(&ses.writequeue)) {
			write_packet();
		}

		if (FD_ISSET(ses.sock, &readfd)) {
			read_packet();
		}

		/* Process the decrypted packet. After this, the read buffer
		 * will be ready for a new packet */
		if (ses.payload != NULL) {
			process_packet();
		}

		/* process pipes etc for the channels */
		if (ses.dataallowed == 1) {
			channelio(&readfd, &writefd);
		}

	} /* for(;;) */
}

/* Check all timeouts which are required. Currently these are the time for
 * user authentication, and the automatic rekeying. */
void checktimeouts() {

	struct timeval tv;
	long secs;

	if (gettimeofday(&tv, 0) < 0) {
		dropbear_exit("Error getting time");
	}

	secs = tv.tv_sec;
	
	if (!ses.authstate.authdone) {
		if (secs - ses.connecttime >= AUTH_TIMEOUT) {
			dropbear_close("Timeout before userauth");
		}
	}

	if (!ses.kexstate.sentkexinit
			&& (secs - ses.kexstate.lastkextime >= KEX_REKEY_TIMEOUT
			|| ses.kexstate.datarecv+ses.kexstate.datatrans >= KEX_REKEY_DATA)){
		TRACE(("rekeying after timeout or max data reached"));
		send_msg_kexinit();
	}
}


/* clean up a session on exit */
void session_cleanup() {
	
	TRACE(("enter session_cleanup"));
	
	/* we can't cleanup if we don't know the session state */
	if (!sessinitdone) {
		return;
	}
	
	m_free(ses.session_id);
	freerunopts(ses.opts);
	m_free(ses.keys);

	chancleanup();

	TRACE(("leave session_cleanup"));
}

/* called only at the start of a session, set up initial state */
static void session_init(int sock, runopts *opts, int childpipe,
		struct sockaddr *remoteaddr) {

	struct timeval tv;
	TRACE(("enter session_init"));

	ses.remoteaddr = remoteaddr;

	ses.addrstring = getaddrstring(remoteaddr);
	ses.hostname = getaddrhostname(remoteaddr);

	ses.sock = sock;
	ses.maxfd = sock;

	ses.childpipe = childpipe;

	ses.opts = opts;

	if (gettimeofday(&tv, 0) < 0) {
		dropbear_exit("Error getting time");
	}

	ses.connecttime = tv.tv_sec;
	
	kexinitialise(); /* initialise the kex state */
	authinitialise(); /* initialise auth state */
	chaninitialise(); /* initialise the channel state */

	ses.writepayload = buf_new(MAX_TRANS_PAYLOAD_LEN);
	ses.transseq = 0;

	ses.readbuf = NULL;
	ses.decryptreadbuf = NULL;
	ses.payload = NULL;
	ses.recvseq = 0;

	ses.expecting = SSH_MSG_KEXINIT;
	ses.dataallowed = 0; /* don't send data yet, we'll wait until after kex */

	/* set all the algos to none */
	ses.keys = (struct key_context*)m_malloc(sizeof(struct key_context));
	ses.newkeys = NULL;
	ses.keys->recv_algo_crypt = &dropbear_nocipher;
	ses.keys->trans_algo_crypt = &dropbear_nocipher;
	
	ses.keys->recv_algo_mac = &dropbear_nohash;
	ses.keys->trans_algo_mac = &dropbear_nohash;

	ses.keys->algo_kex = -1;
	ses.keys->algo_hostkey = -1;
	ses.keys->recv_algo_comp = DROPBEAR_COMP_NONE;
	ses.keys->trans_algo_comp = DROPBEAR_COMP_NONE;

#ifndef DISABLE_ZLIB
	ses.keys->recv_zstream = NULL;
	ses.keys->trans_zstream = NULL;
#endif

	/* key exchange buffers */
	ses.session_id = NULL;
	ses.kexhashbuf = NULL;
	ses.transkexinit = NULL;
	ses.dh_K = NULL;

	sessinitdone = 1;

	TRACE(("leave session_init"));
}

static void session_identification() {

	char linebuf[256];
	int len = 0;
	int i;
	char done = 0;

	/* write our version string, this blocks */
	if (atomicio(write, ses.sock, LOCAL_IDENT "\r\n",
				strlen(LOCAL_IDENT "\r\n")) == DROPBEAR_FAILURE) {
		dropbear_exit("Error writing ident string");
	}

	/* now read the client version string, there are allowed to be other lines
	 * before the "SSH-*" line. We allow a max of 9 lines before it, just for
	 * sanity */
	for (i = 0; i < 10; i++) {
		len = readln(ses.sock, linebuf, 256);
		if (len < 0) {
			break;
		}
		if (len >= 4 && linebuf[0] == 'S'
					 && linebuf[1] == 'S'
					 && linebuf[2] == 'H'
					 && linebuf[3] == '-') {
			/* start of line matches */
			done = 1;
			break;
		}
	}

	if (!done) {
		dropbear_exit("Failed to get remote ident");
	} else {
		/* linebuf is already null terminated */
		ses.remoteident = m_malloc(len);
		memcpy(ses.remoteident, linebuf, len);
	}

	TRACE(("remoteident: %s", ses.remoteident));

}
