#include "includes.h"
#include "listener.h"
#include "session.h"
#include "dbutil.h"

void listeners_initialise() {

	/* just one slot to start with */
	ses.listeners = (struct Listener**)m_malloc(sizeof(struct Listener*));
	ses.listensize = 1;
	ses.listeners[0] = NULL;

}

void set_listener_fds(fd_set * readfds) {

	unsigned int i;
	struct Listener *listener;

	/* check each in turn */
	for (i = 0; i < ses.listensize; i++) {
		listener = ses.listeners[i];
		if (listener != NULL) {
			TRACE(("set listener fd %d", listener->sock));
			FD_SET(listener->sock, readfds);
		}
	}
}


void handle_listeners(fd_set * readfds) {

	unsigned int i;
	struct Listener *listener;

	/* check each in turn */
	for (i = 0; i < ses.listensize; i++) {
		listener = ses.listeners[i];
		if (listener != NULL) {
		TRACE(("handle listener num %d fd %d", i, listener->sock));
			if (FD_ISSET(listener->sock, readfds)) {
				listener->accepter(listener);
			}
		}
	}
}


/* accepter(int fd, void* typedata) is a function to accept connections, 
 * cleanup(void* typedata) happens when cleaning up */
struct Listener* new_listener(int sock, int type, void* typedata, 
		void (*accepter)(struct Listener*), 
		void (*cleanup)(struct Listener*)) {

	unsigned int i, j;
	struct Listener *newlisten = NULL;
	/* try get a new structure to hold it */
	for (i = 0; i < ses.listensize; i++) {
		if (ses.listeners[i] == NULL) {
			break;
		}
	}

	/* or create a new one */
	if (i == ses.listensize) {
		if (ses.listensize > MAX_LISTENERS) {
			TRACE(("leave newlistener: too many already"));
			close(sock);
			return NULL;
		}
		
		ses.listeners = (struct Listener**)m_realloc(ses.listeners,
				(ses.listensize+LISTENER_EXTEND_SIZE)
				*sizeof(struct Listener*));

		ses.listensize += LISTENER_EXTEND_SIZE;

		for (j = i; j < ses.listensize; j++) {
			ses.listeners[j] = NULL;
		}
	}

	ses.maxfd = MAX(ses.maxfd, sock);

	TRACE(("new listener num %d fd %d", i, sock));

	newlisten = (struct Listener*)m_malloc(sizeof(struct Listener));
	newlisten->index = i;
	newlisten->type = type;
	newlisten->typedata = typedata;
	newlisten->sock = sock;
	newlisten->accepter = accepter;
	newlisten->cleanup = cleanup;

	ses.listeners[i] = newlisten;
	return newlisten;
}

/* Return the first listener which matches the type-specific comparison
 * function. Particularly needed for global requests, like tcp */
struct Listener * get_listener(int type, void* typedata,
		int (*match)(void*, void*)) {

	unsigned int i;
	struct Listener* listener;

	for (i = 0, listener = ses.listeners[i]; i < ses.listensize; i++) {
		if (listener->type == type
				&& match(typedata, listener->typedata)) {
			return listener;
		}
	}

	return NULL;
}

void remove_listener(struct Listener* listener) {

	if (listener->cleanup) {
		listener->cleanup(listener);
	}

	close(listener->sock);
	ses.listeners[listener->index] = NULL;
	m_free(listener);

}
