#include "includes.h"
#include "ssh.h"
#include "tcp-accept.h"
#include "dbutil.h"
#include "session.h"
#include "buffer.h"
#include "packet.h"
#include "listener.h"
#include "runopts.h"

#ifndef DISABLE_TCP_ACCEPT

static void accept_tcp(struct Listener *listener, int sock) {

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

		buf_putstring(ses.writepayload, tcpinfo->addr, strlen(tcpinfo->addr));
		buf_putint(ses.writepayload, tcpinfo->port);
		buf_putstring(ses.writepayload, ipstring, strlen(ipstring));
		buf_putint(ses.writepayload, atol(portstring));
		encrypt_packet();

	} else {
		/* XXX debug? */
		close(fd);
	}
}

static void cleanup_tcp(struct Listener *listener) {

	struct TCPListener *tcpinfo = (struct TCPListener*)(listener->typedata);

	m_free(tcpinfo->addr);
	m_free(tcpinfo);
}


int listen_tcpfwd(struct TCPListener* tcpinfo) {

	char portstring[6]; /* "65535\0" */
	int socks[DROPBEAR_MAX_SOCKS];
	struct Listener *listener = NULL;
	int nsocks;

	TRACE(("enter listen_tcpfwd"));

	/* first we try to bind, so don't need to do so much cleanup on failure */
	snprintf(portstring, sizeof(portstring), "%d", tcpinfo->port);
	nsocks = dropbear_listen(tcpinfo->addr, portstring, socks, 
			DROPBEAR_MAX_SOCKS, NULL, &ses.maxfd);
	if (nsocks < 0) {
		TRACE(("leave listen_tcpfwd: dropbear_listen failed"));
		return DROPBEAR_FAILURE;
	}

	listener = new_listener(socks, nsocks, CHANNEL_ID_TCPFORWARDED, tcpinfo, 
			accept_tcp, cleanup_tcp);

	if (listener == NULL) {
		m_free(tcpinfo);
		TRACE(("leave listen_tcpfwd: listener failed"));
		return DROPBEAR_FAILURE;
	}

	TRACE(("leave listen_tcpfwd: success"));
	return DROPBEAR_SUCCESS;
}

#endif /* DISABLE_REMOTETCPFWD */
