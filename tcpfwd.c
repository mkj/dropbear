#include "includes.h"
#include "tcpfwd.h"
#include "session.h"
#include "dbutil.h"

void tcp_fwd_initialise() {

	/* just one slot to start with */
	ses.tcplisteners = 
		(struct TCPListener**)m_malloc(sizeof(struct TCPListener*));
	ses.tcplistensize = 1;
	ses.tcplisteners[0] = NULL;

}

void set_tcp_fwd_fds(fd_set * readfds) {

	unsigned int i;
	struct TCPListener *listener;

	/* check each in turn */
	for (i = 0; i < ses.tcplistensize; i++) {
		listener = ses.tcplisteners[i];
		if (listener != NULL) {
			FD_SET(listener->sock, readfds);
		}
	}
}


void handle_tcp_fwd(fd_set * readfds) {

	unsigned int i;
	struct TCPListener *listener;

	/* check each in turn */
	for (i = 0; i < ses.tcplistensize; i++) {
		listener = ses.tcplisteners[i];
		if (listener != NULL) {
			if (FD_ISSET(listener->sock, readfds)) {
				listener->accepter(listener);
			}
		}
	}
}


/* accepter(int fd, void* typedata) is a function to accept connections, 
 * cleanup(void* typedata) happens when cleaning up */
int new_fwd(int sock, int type, void* typedata, 
		void (*accepter)(struct TCPListener*), 
		void (*cleanup)(struct TCPListener*)) {

	unsigned int i, j;
	struct TCPListener *newtcp = NULL;
	/* try get a new structure to hold it */
	for (i = 0; i < ses.tcplistensize; i++) {
		if (ses.tcplisteners[i] == NULL) {
			break;
		}
	}

	/* or create a new one */
	if (i == ses.tcplistensize) {
		if (ses.tcplistensize > MAX_TCPLISTENERS) {
			TRACE(("leave newlistener: too many already"));
			close(sock);
			return DROPBEAR_FAILURE;
		}
		
		ses.tcplisteners = (struct TCPListener**)m_realloc(ses.tcplisteners,
				(ses.tcplistensize+TCP_EXTEND_SIZE)
				*sizeof(struct TCPListener*));

		ses.tcplistensize += TCP_EXTEND_SIZE;

		for (j = i; j < ses.tcplistensize; j++) {
			ses.tcplisteners[j] = NULL;
		}
	}

	ses.maxfd = MAX(ses.maxfd, sock);

	newtcp = (struct TCPListener*)m_malloc(sizeof(struct TCPListener));
	newtcp->index = i;
	newtcp->type = type;
	newtcp->typedata = typedata;
	newtcp->sock = sock;
	newtcp->accepter = accepter;
	newtcp->cleanup = cleanup;

	ses.tcplisteners[i] = newtcp;
	return DROPBEAR_SUCCESS;
}

/* Return the first listener which matches the type-specific comparison
 * function */
struct TCPListener * get_listener(int type, void* typedata,
		int (*match)(void*, void*)) {

	unsigned int i;
	struct TCPListener* listener;

	for (i = 0, listener = ses.tcplisteners[i]; i < ses.tcplistensize; i++) {
		if (listener->type == type
				&& match(typedata, listener->typedata)) {
			return listener;
		}
	}

	return NULL;
}

void remove_listener(struct TCPListener* listener) {

	if (listener->cleanup) {
		listener->cleanup(listener);
	}

	close(listener->sock);
	ses.tcplisteners[listener->index] = NULL;
	m_free(listener);

}
