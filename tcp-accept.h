#ifndef _REMOTETCPFWD_H
#define _REMOTETCPFWD_H

struct TCPListener {

	/* Local ones */
	unsigned char *localaddr; /* Can be NULL */
	unsigned int localport;
	/* Remote ones: */
	unsigned char *remoteaddr;
	unsigned int remoteport;
	const struct ChanType *chantype;

};

void recv_msg_global_request_remotetcp();
int listen_tcpfwd(struct TCPListener* tcpinfo);

#endif /* _REMOTETCPFWD_H */
