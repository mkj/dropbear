#include "tcpfwd.h"

int newdirecttcp(struct Channel * chan) {

	unsigned char* desthost;
	unsigned int destport;
	unsigned char* orighost;
	unsigned int origport;

	desthost = buf_getstring(ses.payload);
	destport = buf_getport(ses.payload);
	orighost = buf_getstring(ses.payload);
	origport = buf_getstring(ses.payload);

	/* need to make sure that our origport matches the range of the
	 * source origport */

}

/* Initiate a new TCP connection - this is non-blocking, so the socket
 * returned will need to be checked for success when it is first written.
 * Similarities with OpenSSH's connect_to() are not coincidental.
 * Returns -1 on failure */
static int newtcp(const char * host, int port, int origport) {

	int sock;
	char portstring[6];
	struct addrinfo *res = NULL, *ai;

	struct addrinfo hints;

	TRACE(("enter newtcp"));

	memset(hints, 0, sizeof(hints));
	/* TCP, either ip4 or ip6 */
	hints.ai_type = SOCK_STREAM;
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
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0 &&
				errno != EINPROGRESS) {
			close(sock);
			TRACE(("TCP connect failed"));
			continue;
		}
	}
}
