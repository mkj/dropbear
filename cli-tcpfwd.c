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




static int cli_localtcp(char* port) {

	struct TCPListener* tcpinfo = NULL;

	tcpinfo = (struct TCPListener*)m_malloc(sizeof(struct TCPListener*));
	tcpinfo->addr = NULL;
	tcpinfo->port = port;
	tcpinfo->chantype = &cli_chan_tcplocal;

	ret = listen_tcpfwd(tcpinfo);

	if (ret == DROPBEAR_FAILURE) {
		DROPBEAR_LOG(LOG_WARNING, "Failed to listen on port %s", port);
		m_free(tcpinfo);
	}
	return ret;
}
