#ifndef _REMOTETCPFWD_H
#define _REMOTETCPFWD_H

struct TCPListener {

	/* sendaddr/sendport are what we send in the channel init request. For a 
	 * forwarded-tcpip request, it's the addr/port we were binding to.
	 * For a direct-tcpip request, it's the addr/port we want the other
	 * end to connect to */
	
	unsigned char *sendaddr;
	unsigned int sendport;

	/* This is for direct-tcpip (ie the client listening), and specifies the
	 * port to listen on. Is unspecified for the server */
	unsigned int listenport;

	const struct ChanType *chantype;

};

void recv_msg_global_request_remotetcp();
int listen_tcpfwd(struct TCPListener* tcpinfo);

#endif /* _REMOTETCPFWD_H */
