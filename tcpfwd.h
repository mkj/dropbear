#ifndef _TCPFWD_H
#define _TCPFWD_H

#define MAX_TCPLISTENERS 20
#define TCP_EXTEND_SIZE 1

struct TCPListener {

	int sock;

	int index; /* index in the array of listeners */

	void (*accepter)(struct TCPListener*);
	void (*cleanup)(struct TCPListener*);

	int type; /* CHANNEL_ID_X11, CHANNEL_ID_AGENT, 
				 CHANNEL_ID_TCPDIRECT (for clients),
				 CHANNEL_ID_TCPFORWARDED (for servers) */

	void *typedata;

};

void tcp_fwd_initialise();
void handle_tcp_fwd(fd_set * readfds);
void set_tcp_fwd_fds(fd_set * readfds);

int new_fwd(int sock, int type, void* typedata, 
		void (*accepter)(struct TCPListener*), 
		void (*cleanup)(struct TCPListener*));

struct TCPListener * get_listener(int type, void* typedata,
		int (*match)(void*, void*));

void remove_listener(struct TCPListener* listener);

#endif /* _TCPFWD_H */
