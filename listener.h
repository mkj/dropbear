#ifndef _LISTENER_H
#define _LISTENER_H

#define MAX_LISTENERS 20
#define LISTENER_EXTEND_SIZE 1

struct Listener {

	int socks[DROPBEAR_MAX_SOCKS];
	unsigned int nsocks;

	int index; /* index in the array of listeners */

	void (*accepter)(struct Listener*, int sock);
	void (*cleanup)(struct Listener*);

	int type; /* CHANNEL_ID_X11, CHANNEL_ID_AGENT, 
				 CHANNEL_ID_TCPDIRECT (for clients),
				 CHANNEL_ID_TCPFORWARDED (for servers) */

	void *typedata;

};

void listeners_initialise();
void handle_listeners(fd_set * readfds);
void set_listener_fds(fd_set * readfds);

struct Listener* new_listener(int socks[], unsigned int nsocks, 
		int type, void* typedata, 
		void (*accepter)(struct Listener*, int sock), 
		void (*cleanup)(struct Listener*));

struct Listener * get_listener(int type, void* typedata,
		int (*match)(void*, void*));

void remove_listener(struct Listener* listener);

#endif /* _LISTENER_H */
