#include "includes.h"
#include "session.h"
#include "dbutil.h"
#include "localtcpfwd.h"

#ifndef DISABLE_LOCALTCPFWD
static int newtcp(const char * host, int port);

/* Called upon creating a new direct tcp channel (ie we connect out to an
 * address */
int newtcpdirect(struct Channel * channel) {

	unsigned char* desthost = NULL;
	unsigned int destport;
	unsigned char* orighost = NULL;
	unsigned int origport;
	int sock;
	int len;
	int ret = DROPBEAR_FAILURE;

	desthost = buf_getstring(ses.payload, &len);
	if (len > MAX_HOST_LEN) {
		TRACE(("leave newtcpdirect: desthost too long"));
		goto out;
	}

	destport = buf_getint(ses.payload);
	
	orighost = buf_getstring(ses.payload, &len);
	if (len > MAX_HOST_LEN) {
		TRACE(("leave newtcpdirect: orighost too long"));
		goto out;
	}

	origport = buf_getint(ses.payload);

	/* best be sure */
	if (origport > 65535 || destport > 65535) {
		TRACE(("leave newtcpdirect: port > 65535"));
		goto out;
	}

	sock = newtcp(desthost, destport);
	if (sock < 0) {
		TRACE(("leave newtcpdirect: sock failed"));
		goto out;
	}

	ses.maxfd = MAX(ses.maxfd, sock);

	/* Note that infd is actually the "outgoing" direction on the
	 * tcp connection, vice versa for outfd.
	 * We don't set outfd, that will get set after the connection's
	 * progress succeeds */
	channel->infd = sock;
	channel->initconn = 1;
	
	ret = DROPBEAR_SUCCESS;

out:
	m_free(desthost);
	m_free(orighost);
	TRACE(("leave newtcpdirect: ret %d", ret));
	return ret;
}

/* Initiate a new TCP connection - this is non-blocking, so the socket
 * returned will need to be checked for success when it is first written.
 * Similarities with OpenSSH's connect_to() are not coincidental.
 * Returns -1 on failure */
static int newtcp(const char * host, int port) {

	int sock;
	char portstring[6];
	struct addrinfo *res = NULL, *ai;
	int val;

	struct addrinfo hints;

	TRACE(("enter newtcp"));

	memset(&hints, 0, sizeof(hints));
	/* TCP, either ip4 or ip6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = PF_UNSPEC;

	snprintf(portstring, sizeof(portstring), "%d", port);
	if (getaddrinfo(host, portstring, &hints, &res) != 0) {
		if (res) {
			freeaddrinfo(res);
		}
		TRACE(("leave newtcp: failed getaddrinfo"));
		return -1;
	}

	ai = res;
	
	/* Use the first socket that works */
	for (ai = res; ai != NULL; ai = ai->ai_next) {
		
		if (ai->ai_family != PF_INET && ai->ai_family != PF_INET6) {
			continue;
		}

		sock = socket(ai->ai_family, SOCK_STREAM, 0);
		if (sock < 0) {
			TRACE(("TCP socket() failed"));
			continue;
		}

		if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
			TRACE(("TCP non-blocking failed"));
			continue;
		}

		/* non-blocking, so it might return without success (EINPROGRESS) */
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			if (errno == EINPROGRESS) {
				TRACE(("connect in progress"));
			} else {
				close(sock);
				TRACE(("TCP connect failed"));
				continue;
			}
		} 
		break;
	}

	freeaddrinfo(res);
	
	if (ai == NULL) {
		return -1;
	}

	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void*)&val, sizeof(val));
	return sock;
}
#endif /* DISABLE_LOCALTCPFWD */
