#ifndef _REMOTETCPFWD_H
#define _REMOTETCPFWD_H

#define MAX_TCPLISTENERS 20
#define TCP_EXTEND_SIZE 1

struct TCPListener {

	int sock;
	unsigned char* addr;
	unsigned int port;

	int index; /* index in the array of listeners */

};

void remotetcpinitialise();
void recv_msg_global_request_remotetcp();
void handleremotetcp(fd_set * readfds);
void setremotetcpfds(fd_set * readfds);

#endif /* _REMOTETCPFWD_H */
