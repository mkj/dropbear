#include "includes.h"
#include "ssh.h"
#include "tcpfwd.h"
#include "dbutil.h"
#include "session.h"
#include "buffer.h"
#include "packet.h"
#include "listener.h"
#include "runopts.h"

#ifndef DISABLE_TCP_ACCEPT


static void cleanup_tcp(struct Listener *listener) {

	struct TCPListener *tcpinfo = (struct TCPListener*)(listener->typedata);

	m_free(tcpinfo->sendaddr);
	m_free(tcpinfo);
}

static void tcp_acceptor(struct Listener *listener, int sock) {

	int fd;
	struct sockaddr_storage addr;
	int len;
	char ipstring[NI_MAXHOST], portstring[NI_MAXSERV];
	struct TCPListener *tcpinfo = (struct TCPListener*)(listener->typedata);

	len = sizeof(addr);

	fd = accept(sock, (struct sockaddr*)&addr, &len);
	if (fd < 0) {
		return;
	}

	if (getnameinfo((struct sockaddr*)&addr, len, ipstring, sizeof(ipstring),
				portstring, sizeof(portstring), 
				NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
		return;
	}

	if (send_msg_channel_open_init(fd, tcpinfo->chantype) == DROPBEAR_SUCCESS) {

		buf_putstring(ses.writepayload, tcpinfo->sendaddr, 
				strlen(tcpinfo->sendaddr));
		buf_putint(ses.writepayload, tcpinfo->sendport);
		buf_putstring(ses.writepayload, ipstring, strlen(ipstring));
		buf_putint(ses.writepayload, atol(portstring));

		encrypt_packet();

	} else {
		/* XXX debug? */
		close(fd);
	}
}

int listen_tcpfwd(struct TCPListener* tcpinfo) {

	char portstring[NI_MAXSERV];
	int socks[DROPBEAR_MAX_SOCKS];
	struct Listener *listener = NULL;
	int nsocks;
	char* errstring = NULL;

	TRACE(("enter listen_tcpfwd"));

	/* first we try to bind, so don't need to do so much cleanup on failure */
	snprintf(portstring, sizeof(portstring), "%d", tcpinfo->listenport);

	/* XXX Note: we're just listening on localhost, no matter what they tell
	 * us. If someone wants to make it listen otherways, then change
	 * the "" argument. but that requires UI changes too */
	nsocks = dropbear_listen("", portstring, socks, 
			DROPBEAR_MAX_SOCKS, &errstring, &ses.maxfd);
	if (nsocks < 0) {
		dropbear_log(LOG_INFO, "TCP forward failed: %s", errstring);
		m_free(errstring);
		TRACE(("leave listen_tcpfwd: dropbear_listen failed"));
		return DROPBEAR_FAILURE;
	}

	listener = new_listener(socks, nsocks, CHANNEL_ID_TCPFORWARDED, tcpinfo, 
			tcp_acceptor, cleanup_tcp);

	if (listener == NULL) {
		m_free(tcpinfo);
		TRACE(("leave listen_tcpfwd: listener failed"));
		return DROPBEAR_FAILURE;
	}

	TRACE(("leave listen_tcpfwd: success"));
	return DROPBEAR_SUCCESS;
}

#endif /* DISABLE_REMOTETCPFWD */
