#include "includes.h"
#include "options.h"
#include "dbutil.h"
#include "tcpfwd.h"
#include "channel.h"
#include "runopts.h"
#include "session.h"
#include "ssh.h"

static int cli_localtcp(unsigned int listenport, const char* remoteaddr,
		unsigned int remoteport);
static int newtcpforwarded(struct Channel * channel);

const struct ChanType cli_chan_tcpremote = {
	1, /* sepfds */
	"forwarded-tcpip",
	newtcpforwarded,
	NULL,
	NULL,
	NULL
};
static const struct ChanType cli_chan_tcplocal = {
	1, /* sepfds */
	"direct-tcpip",
	NULL,
	NULL,
	NULL,
	NULL
};

void setup_localtcp() {

	int ret;

	TRACE(("enter setup_localtcp"));

	if (cli_opts.localfwds == NULL) {
		TRACE(("cli_opts.localfwds == NULL"));
	}

	while (cli_opts.localfwds != NULL) {
		ret = cli_localtcp(cli_opts.localfwds->listenport,
				cli_opts.localfwds->connectaddr,
				cli_opts.localfwds->connectport);
		if (ret == DROPBEAR_FAILURE) {
			dropbear_log(LOG_WARNING, "Failed local port forward %d:%s:%d",
					cli_opts.localfwds->listenport,
					cli_opts.localfwds->connectaddr,
					cli_opts.localfwds->connectport);
		}

		cli_opts.localfwds = cli_opts.localfwds->next;
	}
	TRACE(("leave setup_localtcp"));

}

static int cli_localtcp(unsigned int listenport, const char* remoteaddr,
		unsigned int remoteport) {

	struct TCPListener* tcpinfo = NULL;
	int ret;

	TRACE(("enter cli_localtcp: %d %s %d", listenport, remoteaddr,
				remoteport));

	tcpinfo = (struct TCPListener*)m_malloc(sizeof(struct TCPListener*));
	tcpinfo->sendaddr = remoteaddr;
	tcpinfo->sendport = remoteport;
	tcpinfo->listenport = listenport;
	tcpinfo->chantype = &cli_chan_tcplocal;

	ret = listen_tcpfwd(tcpinfo);

	if (ret == DROPBEAR_FAILURE) {
		m_free(tcpinfo);
	}
	TRACE(("leave cli_localtcp: %d", ret));
	return ret;
}

static void send_msg_global_request_remotetcp(int port) {

	TRACE(("enter send_msg_global_request_remotetcp"));

	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_GLOBAL_REQUEST);
	buf_putstring(ses.writepayload, "tcpip-forward", 13);
	buf_putbyte(ses.writepayload, 0);
	buf_putstring(ses.writepayload, "0.0.0.0", 7); /* TODO: IPv6? */
	buf_putint(ses.writepayload, port);

	encrypt_packet();

	TRACE(("leave send_msg_global_request_remotetcp"));
}

void setup_remotetcp() {

	struct TCPFwdList * iter = NULL;

	TRACE(("enter setup_remotetcp"));

	if (cli_opts.remotefwds == NULL) {
		TRACE(("cli_opts.remotefwds == NULL"));
	}

	iter = cli_opts.remotefwds;

	while (iter != NULL) {
		send_msg_global_request_remotetcp(iter->listenport);
		iter = iter->next;
	}
	TRACE(("leave setup_remotetcp"));
}

static int newtcpforwarded(struct Channel * channel) {

	unsigned int origport;
	struct TCPFwdList * iter = NULL;
	char portstring[NI_MAXSERV];
	int sock;
	int err = SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;

	/* We don't care what address they connected to */
	buf_eatstring(ses.payload);

	origport = buf_getint(ses.payload);

	/* Find which port corresponds */
	iter = cli_opts.remotefwds;

	while (iter != NULL) {
		if (origport == iter->listenport) {
			break;
		}
		iter = iter->next;
	}

	if (iter == NULL) {
		/* We didn't request forwarding on that port */
		dropbear_log(LOG_INFO, "Server send unrequested port, from port %d", 
										origport);
		goto out;
	}
	
	snprintf(portstring, sizeof(portstring), "%d", iter->connectport);
	sock = connect_remote(iter->connectaddr, portstring, 1, NULL);
	if (sock < 0) {
		TRACE(("leave newtcpdirect: sock failed"));
		err = SSH_OPEN_CONNECT_FAILED;
		goto out;
	}

	ses.maxfd = MAX(ses.maxfd, sock);

	/* Note that infd is actually the "outgoing" direction on the
	 * tcp connection, vice versa for outfd.
	 * We don't set outfd, that will get set after the connection's
	 * progress succeeds */
	channel->infd = sock;
	channel->initconn = 1;
	
	err = SSH_OPEN_IN_PROGRESS;

out:
	TRACE(("leave newtcpdirect: err %d", err));
	return err;
}
