#include "includes.h"
#include "session.h"
#include "dbutil.h"
#include "channel.h"
#include "tcp-connect.h"
#include "runopts.h"

#ifndef DISABLE_TCP_CONNECT

/* Called upon creating a new direct tcp channel (ie we connect out to an
 * address */
int newtcpdirect(struct Channel * channel) {

	unsigned char* desthost = NULL;
	unsigned int destport;
	unsigned char* orighost = NULL;
	unsigned int origport;
	char portstring[NI_MAXSERV];
	int sock;
	int len;
	int ret = DROPBEAR_FAILURE;

	if (opts.nolocaltcp) {
		TRACE(("leave newtcpdirect: local tcp forwarding disabled"));
		goto out;
	}

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

	snprintf(portstring, sizeof(portstring), "%d", destport);
	sock = connect_remote(desthost, portstring, 1, NULL);
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

#endif /* DISABLE_TCPFWD_DIRECT */
