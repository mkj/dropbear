#include "includes.h"
#include "ssh.h"
#include "tcp-accept.h"
#include "tcp-connect.h"
#include "dbutil.h"
#include "session.h"
#include "buffer.h"
#include "packet.h"
#include "listener.h"
#include "runopts.h"

#ifndef DISABLE_SVR_REMOTETCPFWD

static void send_msg_request_success();
static void send_msg_request_failure();
static int svr_cancelremotetcp();
static int svr_remotetcpreq();


const struct ChanType svr_chan_tcpdirect = {
	1, /* sepfds */
	"direct-tcpip",
	newtcpdirect, /* init */
	NULL, /* checkclose */
	NULL, /* reqhandler */
	NULL /* closehandler */
};

static const struct ChanType svr_chan_tcpremote = {
	1, /* sepfds */
	"forwarded-tcpip",
	NULL,
	NULL,
	NULL,
	NULL
};

/* At the moment this is completely used for tcp code (with the name reflecting
 * that). If new request types are added, this should be replaced with code
 * similar to the request-switching in chansession.c */
void recv_msg_global_request_remotetcp() {

	unsigned char* reqname = NULL;
	unsigned int namelen;
	unsigned int wantreply = 0;
	int ret = DROPBEAR_FAILURE;

	TRACE(("enter recv_msg_global_request_remotetcp"));

	if (opts.noremotetcp) {
		TRACE(("leave recv_msg_global_request_remotetcp: remote tcp forwarding disabled"));
		goto out;
	}

	reqname = buf_getstring(ses.payload, &namelen);
	wantreply = buf_getbyte(ses.payload);

	if (namelen > MAXNAMLEN) {
		TRACE(("name len is wrong: %d", namelen));
		goto out;
	}

	if (strcmp("tcpip-forward", reqname) == 0) {
		ret = svr_remotetcpreq();
	} else if (strcmp("cancel-tcpip-forward", reqname) == 0) {
		ret = svr_cancelremotetcp();
	} else {
		TRACE(("reqname isn't tcpip-forward: '%s'", reqname));
	}

out:
	if (wantreply) {
		if (ret == DROPBEAR_SUCCESS) {
			send_msg_request_success();
		} else {
			send_msg_request_failure();
		}
	}

	m_free(reqname);

	TRACE(("leave recv_msg_global_request"));
}


static void send_msg_request_success() {

	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_REQUEST_SUCCESS);
	encrypt_packet();

}

static void send_msg_request_failure() {

	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_REQUEST_FAILURE);
	encrypt_packet();

}

static int matchtcp(void* typedata1, void* typedata2) {

	const struct TCPListener *info1 = (struct TCPListener*)typedata1;
	const struct TCPListener *info2 = (struct TCPListener*)typedata2;

	return (info1->sendport == info2->sendport)
			&& (info1->chantype == info2->chantype)
			&& (strcmp(info1->sendaddr, info2->sendaddr) == 0);
}

static int svr_cancelremotetcp() {

	int ret = DROPBEAR_FAILURE;
	unsigned char * bindaddr = NULL;
	unsigned int addrlen;
	unsigned int port;
	struct Listener * listener = NULL;
	struct TCPListener tcpinfo;

	TRACE(("enter cancelremotetcp"));

	bindaddr = buf_getstring(ses.payload, &addrlen);
	if (addrlen > MAX_IP_LEN) {
		TRACE(("addr len too long: %d", addrlen));
		goto out;
	}

	port = buf_getint(ses.payload);

	tcpinfo.sendaddr = bindaddr;
	tcpinfo.sendport = port;
	listener = get_listener(CHANNEL_ID_TCPFORWARDED, &tcpinfo, matchtcp);
	if (listener) {
		remove_listener( listener );
		ret = DROPBEAR_SUCCESS;
	}

out:
	m_free(bindaddr);
	TRACE(("leave cancelremotetcp"));
	return ret;
}

static int svr_remotetcpreq() {

	int ret = DROPBEAR_FAILURE;
	unsigned char * bindaddr = NULL;
	unsigned int addrlen;
	struct TCPListener *tcpinfo = NULL;
	unsigned int port;

	TRACE(("enter remotetcpreq"));

	/* NOTE: at this stage, we ignore bindaddr. see below and listen_tcpfwd */
	bindaddr = buf_getstring(ses.payload, &addrlen);
	if (addrlen > MAX_IP_LEN) {
		TRACE(("addr len too long: %d", addrlen));
		goto out;
	}

	port = buf_getint(ses.payload);

	if (port == 0) {
		dropbear_log(LOG_INFO, "Server chosen tcpfwd ports are unsupported");
		goto out;
	}

	if (port < 1 || port > 65535) {
		TRACE(("invalid port: %d", port));
		goto out;
	}

	if (!ses.allowprivport && port < IPPORT_RESERVED) {
		TRACE(("can't assign port < 1024 for non-root"));
		goto out;
	}

	tcpinfo = (struct TCPListener*)m_malloc(sizeof(struct TCPListener));
	tcpinfo->sendaddr = bindaddr;
	TRACE(("sendport = %d", port));
	tcpinfo->sendport = port;
	tcpinfo->chantype = &svr_chan_tcpremote;

	/* Note: bindaddr is actually ignored by listen_tcpfwd, since
	 * we only want to bind to localhost */
	ret = listen_tcpfwd(tcpinfo);

out:
	if (ret == DROPBEAR_FAILURE) {
		/* we only free it if a listener wasn't created, since the listener
		 * has to remember it if it's to be cancelled */
		m_free(tcpinfo->sendaddr);
		m_free(tcpinfo);
	}
	TRACE(("leave remotetcpreq"));
	return ret;
}
#endif
