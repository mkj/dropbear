#include "includes.h"
#include "session.h"
#include "dbutil.h"
#include "kex.h"
#include "ssh.h"
#include "packet.h"
#include "tcpfwd-direct.h"
#include "tcpfwd-remote.h"
#include "channel.h"
#include "random.h"
#include "service.h"
#include "runopts.h"
#include "chansession.h"

static void cli_remoteclosed();
static void cli_sessionloop();
static void cli_session_init();
static void cli_finished();

struct clientsession cli_ses; /* GLOBAL */

static const packettype cli_packettypes[] = {
	/* TYPE, AUTHREQUIRED, FUNCTION */
	{SSH_MSG_KEXINIT, recv_msg_kexinit},
	{SSH_MSG_KEXDH_REPLY, recv_msg_kexdh_reply}, // client
	{SSH_MSG_NEWKEYS, recv_msg_newkeys},
	{SSH_MSG_SERVICE_ACCEPT, recv_msg_service_accept}, // client
	{SSH_MSG_CHANNEL_DATA, recv_msg_channel_data},
	{SSH_MSG_CHANNEL_WINDOW_ADJUST, recv_msg_channel_window_adjust},
	{SSH_MSG_GLOBAL_REQUEST, recv_msg_global_request_remotetcp},
	{SSH_MSG_CHANNEL_REQUEST, recv_msg_channel_request},
	{SSH_MSG_CHANNEL_OPEN, recv_msg_channel_open},
	{SSH_MSG_CHANNEL_EOF, recv_msg_channel_eof},
	{SSH_MSG_CHANNEL_CLOSE, recv_msg_channel_close},
	{SSH_MSG_CHANNEL_OPEN_CONFIRMATION, recv_msg_channel_open_confirmation},
	{SSH_MSG_CHANNEL_OPEN_FAILURE, recv_msg_channel_open_failure},
	{SSH_MSG_USERAUTH_FAILURE, recv_msg_userauth_failure}, // client
	{SSH_MSG_USERAUTH_SUCCESS, recv_msg_userauth_success}, // client
	{SSH_MSG_USERAUTH_BANNER, recv_msg_userauth_banner}, // client
	{0, 0} /* End */
};

static const struct ChanType *cli_chantypes[] = {
	/* &chan_tcpdirect etc, though need to only allow if we've requested
	 * that forwarding */
	NULL /* Null termination */
};

void cli_session(int sock, char* remotehost) {

	crypto_init();
	common_session_init(sock, remotehost);

	chaninitialise(cli_chantypes);


	/* Set up cli_ses vars */
	cli_session_init();

	/* Ready to go */
	sessinitdone = 1;

	/* Exchange identification */
	session_identification();

	seedrandom();

	send_msg_kexinit();

	/* XXX here we do stuff differently */

	session_loop(cli_sessionloop);

	/* Not reached */

}

static void cli_session_init() {

	cli_ses.state = STATE_NOTHING;
	cli_ses.kex_state = KEX_NOTHING;

	cli_ses.tty_raw_mode = 0;
	cli_ses.winchange = 0;

	/* For printing "remote host closed" for the user */
	ses.remoteclosed = cli_remoteclosed;
	ses.buf_match_algo = cli_buf_match_algo;

	/* packet handlers */
	ses.packettypes = cli_packettypes;

	ses.isserver = 0;
}

/* This function drives the progress of the session - it initiates KEX,
 * service, userauth and channel requests */
static void cli_sessionloop() {

	TRACE(("enter cli_sessionloop"));

	if (ses.lastpacket == SSH_MSG_KEXINIT && cli_ses.kex_state == KEX_NOTHING) {
		cli_ses.kex_state = KEXINIT_RCVD;
	}

	if (cli_ses.kex_state == KEXINIT_RCVD) {

		/* We initiate the KEXDH. If DH wasn't the correct type, the KEXINIT
		 * negotiation would have failed. */
		send_msg_kexdh_init();
		cli_ses.kex_state = KEXDH_INIT_SENT;
		TRACE(("leave cli_sessionloop: done with KEXINIT_RCVD"));
		return;
	}

	/* A KEX has finished, so we should go back to our KEX_NOTHING state */
	if (cli_ses.kex_state != KEX_NOTHING && ses.kexstate.recvkexinit == 0
			&& ses.kexstate.sentkexinit == 0) {
		cli_ses.kex_state = KEX_NOTHING;
	}

	/* We shouldn't do anything else if a KEX is in progress */
	if (cli_ses.kex_state != KEX_NOTHING) {
		TRACE(("leave cli_sessionloop: kex_state != KEX_NOTHING"));
		return;
	}

	/* We should exit if we haven't donefirstkex: we shouldn't reach here
	 * in normal operation */
	if (ses.kexstate.donefirstkex == 0) {
		TRACE(("XXX XXX might be bad! leave cli_sessionloop: haven't donefirstkex"));
		return;
	}

	switch (cli_ses.state) {

		case STATE_NOTHING:
			/* We've got the transport layer sorted, we now need to request
			 * userauth */
			send_msg_service_request(SSH_SERVICE_USERAUTH);
			cli_ses.state = SERVICE_AUTH_REQ_SENT;
			TRACE(("leave cli_sessionloop: sent userauth service req"));
			return;

		/* userauth code */
		case SERVICE_AUTH_ACCEPT_RCVD:
			cli_auth_getmethods();
			cli_ses.state = USERAUTH_METHODS_SENT;
			TRACE(("leave cli_sessionloop: sent userauth methods req"));
			return;
			
		case USERAUTH_FAIL_RCVD:
			cli_auth_try();
			TRACE(("leave cli_sessionloop: cli_auth_try"));
			return;

			/*
		case USERAUTH_SUCCESS_RCVD:
			send_msg_service_request(SSH_SERVICE_CONNECTION);
			cli_ses.state = SERVICE_CONN_REQ_SENT;
			TRACE(("leave cli_sessionloop: sent ssh-connection service req"));
			return;
			*/

		case USERAUTH_SUCCESS_RCVD:
			cli_send_chansess_request();
			TRACE(("leave cli_sessionloop: cli_send_chansess_request"));
			cli_ses.state = SESSION_RUNNING;
			return;

		case SESSION_RUNNING:
			if (ses.chancount < 1) {
				cli_finished();
			}

			if (cli_ses.winchange) {
				cli_chansess_winchange();
			}
			return;

		/* XXX more here needed */


	default:
		break;
	}

	TRACE(("leave cli_sessionloop: fell out"));

}

void cli_session_cleanup() {

	if (!sessinitdone) {
		return;
	}
	cli_tty_cleanup();

}

static void cli_finished() {

	cli_session_cleanup();
	common_session_cleanup();
	fprintf(stderr, "Connection to %s@%s:%s closed.\n", cli_opts.username,
			cli_opts.remotehost, cli_opts.remoteport);
	exit(EXIT_SUCCESS);
}



/* called when the remote side closes the connection */
static void cli_remoteclosed() {

	/* XXX TODO perhaps print a friendlier message if we get this but have
	 * already sent/received disconnect message(s) ??? */
	close(ses.sock);
	ses.sock = -1;
	dropbear_exit("remote closed the connection");
}

/* Operates in-place turning dirty (untrusted potentially containing control
 * characters) text into clean text. */
void cleantext(unsigned char* dirtytext) {

	unsigned int i, j;
	unsigned char c, lastchar;

	j = 0;
	for (i = 0; dirtytext[i] != '\0'; i++) {

		c = dirtytext[i];
		/* We can ignore '\r's */
		if ( (c >= ' ' && c <= '~') || c == '\n' || c == '\t') {
			dirtytext[j] = c;
			j++;
		}
	}
	/* Null terminate */
	dirtytext[j] = '\0';
}
