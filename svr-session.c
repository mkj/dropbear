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
#include "dbutil.h"
#include "packet.h"
#include "algo.h"
#include "buffer.h"
#include "dss.h"
#include "ssh.h"
#include "random.h"
#include "kex.h"
#include "channel.h"
#include "chansession.h"
#include "atomicio.h"
#include "tcpfwd-direct.h"

static void svr_remoteclosed();

struct serversession svr_ses;

const struct ChanType *chantypes[] = {
	&svrchansess,
	&chan_tcpdirect,
	NULL /* Null termination is mandatory. */
};


void svr_session(int sock, runopts *opts, int childpipe, 
		struct sockaddr* remoteaddr) {

	fd_set readfd, writefd;
	struct timeval timeout;
	int val;
	
	crypto_init();
	common_session_init(sock, opts);

	ses.remoteaddr = remoteaddr;
	ses.remotehost = getaddrhostname(remoteaddr);

	/* Initialise server specific parts of the session */
	svr_ses.childpipe = childpipe;
	authinitialise();
	chaninitialise(chantypes);
	svr_chansessinitialise();

	if (gettimeofday(&timeout, 0) < 0) {
		dropbear_exit("Error getting time");
	}

	ses.connecttimeout = timeout.tv_sec + AUTH_TIMEOUT;

	/* set up messages etc */
	session_remoteclosed = svr_remoteclosed;

	/* We're ready to go now */
	sessinitdone = 1;

	/* exchange identification, version etc */
	session_identification();

	seedrandom();

	/* start off with key exchange */
	send_msg_kexinit();

	FD_ZERO(&readfd);
	FD_ZERO(&writefd);

	/* main loop, select()s for all sockets in use */
	for(;;) {

		timeout.tv_sec = SELECT_TIMEOUT;
		timeout.tv_usec = 0;
		FD_ZERO(&writefd);
		FD_ZERO(&readfd);
		assert(ses.payload == NULL);
		if (ses.sock != -1) {
			FD_SET(ses.sock, &readfd);
			if (!isempty(&ses.writequeue)) {
				FD_SET(ses.sock, &writefd);
			}
		}

		/* set up for channels which require reading/writing */
		if (ses.dataallowed) {
			setchannelfds(&readfd, &writefd);
		}
		val = select(ses.maxfd+1, &readfd, &writefd, NULL, &timeout);

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

		/* check for auth timeout, rekeying required etc */
		checktimeouts();
		
		if (val == 0) {
			/* timeout */
			TRACE(("select timeout"));
			continue;
		}

		/* process session socket's incoming/outgoing data */
		if (ses.sock != -1) {
			if (FD_ISSET(ses.sock, &writefd) && !isempty(&ses.writequeue)) {
				write_packet();
			}

			if (FD_ISSET(ses.sock, &readfd)) {
				read_packet();
			}
			
			/* Process the decrypted packet. After this, the read buffer
			 * will be ready for a new packet */
			if (ses.payload != NULL) {
				svr_process_packet();
			}
		}

		/* process pipes etc for the channels, ses.dataallowed == 0
		 * during rekeying ) */
		if (ses.dataallowed) {
			channelio(&readfd, &writefd);
		}

	} /* for(;;) */
}

/* failure exit - format must be <= 100 chars */
void svr_dropbear_exit(int exitcode, const char* format, va_list param) {

	char fmtbuf[300];

	if (!sessinitdone) {
		/* before session init */
		snprintf(fmtbuf, sizeof(fmtbuf), 
				"premature exit: %s", format);
	} else if (svr_ses.authstate.authdone) {
		/* user has authenticated */
		snprintf(fmtbuf, sizeof(fmtbuf),
				"exit after auth (%s): %s", 
				svr_ses.authstate.printableuser, format);
	} else if (svr_ses.authstate.printableuser) {
		/* we have a potential user */
		snprintf(fmtbuf, sizeof(fmtbuf), 
				"exit before auth (user '%s', %d fails): %s",
				svr_ses.authstate.printableuser, svr_ses.authstate.failcount, format);
	} else {
		/* before userauth */
		snprintf(fmtbuf, sizeof(fmtbuf), 
				"exit before auth: %s", format);
	}

	if (errno != 0) {
		/* XXX - is this valid? */
		snprintf(fmtbuf, sizeof(fmtbuf), "%s [%d %s]", fmtbuf, 
				errno, strerror(errno));
	}

	_dropbear_log(LOG_INFO, fmtbuf, param);

	/* must be after we've done with username etc */
	common_session_cleanup();

	exit(exitcode);

}

/* priority is priority as with syslog() */
void svr_dropbear_log(int priority, const char* format, va_list param) {

	char printbuf[1024];
	char datestr[20];
	time_t timesec;
	int havetrace = 0;

	vsnprintf(printbuf, sizeof(printbuf), format, param);

#ifndef DISABLE_SYSLOG
	if (usingsyslog) {
		syslog(priority, "%s", printbuf);
	}
#endif

	/* if we are using DEBUG_TRACE, we want to print to stderr even if
	 * syslog is used, so it is included in error reports */
#ifdef DEBUG_TRACE
	havetrace = 1;
#endif

	if (!usingsyslog || havetrace)
	{
		timesec = time(NULL);
		if (strftime(datestr, sizeof(datestr), "%b %d %H:%M:%S", 
					localtime(&timesec)) == 0) {
			datestr[0] = '?'; datestr[1] = '\0';
		}
		fprintf(stderr, "[%d] %s %s\n", getpid(), datestr, printbuf);
	}
}

/* called when the remote side closes the connection */
static void svr_remoteclosed() {

	close(ses.sock);
	ses.sock = -1;
	dropbear_close("Exited normally");

}

