#include "includes.h"
#include "ssh.h"
#include "remotetcpfwd.h"
#include "dbutil.h"
#include "session.h"
#include "buffer.h"
#include "packet.h"
#include "tcpfwd.h"

#ifndef DISABLE_REMOTETCPFWD

struct RemoteTCP {

	unsigned char* addr;
	unsigned int port;

};

static void send_msg_request_success();
static void send_msg_request_failure();
static int cancelremotetcp();
static int remotetcpreq();
static int newlistener(unsigned char* bindaddr, unsigned int port);
static void acceptremote(struct TCPListener *listener);

/* At the moment this is completely used for tcp code (with the name reflecting
 * that). If new request types are added, this should be replaced with code
 * similar to the request-switching in chansession.c */
void recv_msg_global_request_remotetcp() {

	unsigned char* reqname = NULL;
	unsigned int namelen;
	unsigned int wantreply = 0;
	int ret = DROPBEAR_FAILURE;

	TRACE(("enter recv_msg_global_request_remotetcp"));

	if (ses.opts->noremotetcp) {
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
		ret = remotetcpreq();
	} else if (strcmp("cancel-tcpip-forward", reqname) == 0) {
		ret = cancelremotetcp();
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

static void acceptremote(struct TCPListener *listener) {

	int fd;
	struct sockaddr addr;
	int len;
	char ipstring[NI_MAXHOST], portstring[NI_MAXSERV];
	struct RemoteTCP *tcpinfo = (struct RemoteTCP*)(listener->typedata);

	len = sizeof(addr);

	fd = accept(listener->sock, &addr, &len);
	if (fd < 0) {
		return;
	}

	if (getnameinfo(&addr, len, ipstring, sizeof(ipstring), portstring,
				sizeof(portstring), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
		return;
	}

	/* XXX XXX XXX - type here needs fixing */
	if (send_msg_channel_open_init(fd, CHANNEL_ID_TCPFORWARDED, 
				"forwarded-tcpip") == DROPBEAR_SUCCESS) {
		buf_putstring(ses.writepayload, tcpinfo->addr,
				strlen(tcpinfo->addr));
		buf_putint(ses.writepayload, tcpinfo->port);
		buf_putstring(ses.writepayload, ipstring, strlen(ipstring));
		buf_putint(ses.writepayload, atol(portstring));
		encrypt_packet();
	}
}

static void cleanupremote(struct TCPListener *listener) {

	struct RemoteTCP *tcpinfo = (struct RemoteTCP*)(listener->typedata);

	m_free(tcpinfo->addr);
	m_free(tcpinfo);
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

	const struct RemoteTCP *info1 = (struct RemoteTCP*)typedata1;
	const struct RemoteTCP *info2 = (struct RemoteTCP*)typedata2;

	return info1->port == info2->port 
			&& (strcmp(info1->addr, info2->addr) == 0);
}

static int cancelremotetcp() {

	int ret = DROPBEAR_FAILURE;
	unsigned char * bindaddr = NULL;
	unsigned int addrlen;
	unsigned int port;
	struct TCPListener * listener = NULL;
	struct RemoteTCP tcpinfo;

	TRACE(("enter cancelremotetcp"));

	bindaddr = buf_getstring(ses.payload, &addrlen);
	if (addrlen > MAX_IP_LEN) {
		TRACE(("addr len too long: %d", addrlen));
		goto out;
	}

	port = buf_getint(ses.payload);

	tcpinfo.addr = bindaddr;
	tcpinfo.port = port;
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

static int remotetcpreq() {

	int ret = DROPBEAR_FAILURE;
	unsigned char * bindaddr = NULL;
	unsigned int addrlen;
	unsigned int port;

	TRACE(("enter remotetcpreq"));

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

	/* XXX matt - server change
	if (ses.authstate.pw->pw_uid != 0
			&& port < IPPORT_RESERVED) {
		TRACE(("can't assign port < 1024 for non-root"));
		goto out;
	}
	*/

	ret = newlistener(bindaddr, port);

out:
	if (ret == DROPBEAR_FAILURE) {
		/* we only free it if a listener wasn't created, since the listener
		 * has to remember it if it's to be cancelled */
		m_free(bindaddr);
	}
	TRACE(("leave remotetcpreq"));
	return ret;
}

static int newlistener(unsigned char* bindaddr, unsigned int port) {

	struct RemoteTCP * tcpinfo = NULL;
	char portstring[6]; /* "65535\0" */
	struct addrinfo *res = NULL, *ai = NULL;
	struct addrinfo hints;
	int sock = -1;
	int ret = DROPBEAR_FAILURE;

	TRACE(("enter newlistener"));

	/* first we try to bind, so don't need to do so much cleanup on failure */
	snprintf(portstring, sizeof(portstring), "%d", port);
	memset(&hints, 0x0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = PF_INET;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

	if (getaddrinfo(bindaddr, portstring, &hints, &res) < 0) {
		TRACE(("leave newlistener: getaddrinfo failed: %s",
					strerror(errno)));
		goto done;
	}

	/* find the first one which works */
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		if (ai->ai_family != PF_INET && ai->ai_family != PF_INET6) {
			continue;
		}

		sock = socket(ai->ai_family, SOCK_STREAM, 0);
		if (sock < 0) {
			TRACE(("socket failed: %s", strerror(errno)));
			goto fail;
		}

		if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			TRACE(("bind failed: %s", strerror(errno)));
			goto fail;
		}

		if (listen(sock, 20) < 0) {
			TRACE(("listen failed: %s", strerror(errno)));
			goto fail;
		}

		if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
			TRACE(("fcntl nonblocking failed: %s", strerror(errno)));
			goto fail;
		}

		/* success */
		break;

fail:
		close(sock);
	}


	if (ai == NULL) {
		TRACE(("no successful sockets"));
		goto done;
	}

	tcpinfo = (struct RemoteTCP*)m_malloc(sizeof(struct RemoteTCP));
	tcpinfo->addr = bindaddr;
	tcpinfo->port = port;

	ret = new_fwd(sock, CHANNEL_ID_TCPFORWARDED, tcpinfo, 
			acceptremote, cleanupremote);

	if (ret == DROPBEAR_FAILURE) {
		m_free(tcpinfo);
	}

done:
	if (res) {
		freeaddrinfo(res);
	}
	
	TRACE(("leave newlistener"));
	return ret;
}

#endif /* DISABLE_REMOTETCPFWD */
