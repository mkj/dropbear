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

static void cli_remoteclosed();
static void cli_sessionloop();

struct clientsession cli_ses; /* GLOBAL */

static const packettype cli_packettypes[] = {
	/* TYPE, AUTHREQUIRED, FUNCTION */
	{SSH_MSG_KEXINIT, recv_msg_kexinit},
	{SSH_MSG_KEXDH_REPLY, recv_msg_kexdh_reply}, // client
	{SSH_MSG_NEWKEYS, recv_msg_newkeys},
	{SSH_MSG_CHANNEL_DATA, recv_msg_channel_data},
	{SSH_MSG_CHANNEL_WINDOW_ADJUST, recv_msg_channel_window_adjust},
	{SSH_MSG_GLOBAL_REQUEST, recv_msg_global_request_remotetcp},
	{SSH_MSG_CHANNEL_REQUEST, recv_msg_channel_request},
	{SSH_MSG_CHANNEL_OPEN, recv_msg_channel_open},
	{SSH_MSG_CHANNEL_EOF, recv_msg_channel_eof},
	{SSH_MSG_CHANNEL_CLOSE, recv_msg_channel_close},
	{SSH_MSG_CHANNEL_OPEN_CONFIRMATION, recv_msg_channel_open_confirmation},
	{SSH_MSG_CHANNEL_OPEN_FAILURE, recv_msg_channel_open_failure},
	{0, 0} /* End */
};

static const struct ChanType *cli_chantypes[] = {
//	&clichansess,
	/* &chan_tcpdirect etc, though need to only allow if we've requested
	 * that forwarding */
	NULL /* Null termination */
};
void cli_session(int sock, char* remotehost) {

	crypto_init();
	common_session_init(sock, remotehost);

	chaninitialise(cli_chantypes);

	/* For printing "remote host closed" for the user */
	session_remoteclosed = cli_remoteclosed;

	/* packet handlers */
	ses.packettypes = cli_packettypes;

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

static void cli_sessionloop() {

	switch (cli_ses.state) {

		KEXINIT_RCVD:
			/* We initiate the KEX. If DH wasn't the correct type, the KEXINIT
			 * negotiation would have failed. */
			send_msg_kexdh_init();
			cli_ses.state = KEXDH_INIT_SENT;
			break;

		default:
			break;
	}

	if (cli_ses.donefirstkex && !cli_ses.authdone) {



}

/* called when the remote side closes the connection */
static void cli_remoteclosed() {

	/* XXX TODO perhaps print a friendlier message if we get this but have
	 * already sent/received disconnect message(s) ??? */
	close(ses.sock);
	ses.sock = -1;
	dropbear_exit("%s closed the connection", ses.remotehost);
}
