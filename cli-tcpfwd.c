#include "includes.h"
#include "options.h"
#include "tcp-accept.h"
#include "tcp-connect.h"
#include "channel.h"

static const struct ChanType cli_chan_tcplocal = {
	1, /* sepfds */
	"direct-tcpip",
	NULL,
	NULL,
	NULL
};

void setup_localtcp() {

	qv

}

static int cli_localtcp(unsigned int listenport, const char* remoteaddr,
		unsigned int remoteport) {

	struct TCPListener* tcpinfo = NULL;

	tcpinfo = (struct TCPListener*)m_malloc(sizeof(struct TCPListener*));
	tcpinfo->sendaddr = remoteaddr;
	tcpinfo->sendport = remoteport;
	tcpinfo->listenport = listenport;
	tcpinfo->chantype = &cli_chan_tcplocal;

	ret = listen_tcpfwd(tcpinfo);

	if (ret == DROPBEAR_FAILURE) {
		m_free(tcpinfo);
	}
	return ret;
}
