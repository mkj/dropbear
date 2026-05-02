/*
 * Dropbear SSH
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * Copyright (c) 2004 by Mihnea Stoenescu
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "ssh.h"
#include "forward.h"
#include "dbutil.h"
#include "session.h"
#include "buffer.h"
#include "packet.h"
#include "listener.h"
#include "runopts.h"
#include "auth.h"
#include "netio.h"

#if !(DROPBEAR_SVR_REMOTETCPFWD || DROPBEAR_SVR_REMOTESTREAMFWD)

/* This is better than SSH_MSG_UNIMPLEMENTED */
void recv_msg_global_request_remotetcp() {
	unsigned int wantreply = 0;

	TRACE(("recv_msg_global_request_remotetcp: remote tcp forwarding not compiled in"))

	buf_eatstring(ses.payload);
	wantreply = buf_getbool(ses.payload);
	if (wantreply) {
		send_msg_request_failure();
	}
}

/* */
#endif /* !DROPBEAR_SVR_REMOTETCPFWD */

static int svr_cancelremotetcp(void);
static int svr_remotetcpreq(int *allocated_listen_port);
#if DROPBEAR_SVR_REMOTESTREAMFWD
static int svr_cancelremotestreamlocal(void);
static int svr_remotestreamlocalreq(void);
#endif
static int newtcpdirect(struct Channel * channel);
#if DROPBEAR_SVR_LOCALSTREAMFWD
static int newstreamlocal(struct Channel * channel);
#endif

#if DROPBEAR_SVR_REMOTETCPFWD
static const struct ChanType svr_chan_tcpremote = {
	"forwarded-tcpip",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

#if DROPBEAR_SVR_REMOTESTREAMFWD
static const struct ChanType svr_chan_streamlocalremote = {
	"forwarded-streamlocal@openssh.com",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif

/* At the moment this is completely used for tcp code (with the name reflecting
 * that). If new request types are added, this should be replaced with code
 * similar to the request-switching in chansession.c */
void recv_msg_global_request_remotetcp() {

	char* reqname = NULL;
	unsigned int namelen;
	unsigned int wantreply = 0;
	int ret = DROPBEAR_FAILURE;

	TRACE(("enter recv_msg_global_request_remotetcp"))

	reqname = buf_getstring(ses.payload, &namelen);
	wantreply = buf_getbool(ses.payload);

	if (svr_opts.noremotetcp || !svr_pubkey_allows_tcpfwd()) {
		TRACE(("leave recv_msg_global_request_remotetcp: remote tcp forwarding disabled"))
		goto out;
	}

	if (namelen > MAX_NAME_LEN) {
		TRACE(("name len is wrong: %d", namelen))
		goto out;
	}

	if (strcmp("tcpip-forward", reqname) == 0) {
		int allocated_listen_port = 0;
		ret = svr_remotetcpreq(&allocated_listen_port);
		/* client expects-port-number-to-make-use-of-server-allocated-ports */
		if (DROPBEAR_SUCCESS == ret) {
			CHECKCLEARTOWRITE();
			buf_putbyte(ses.writepayload, SSH_MSG_REQUEST_SUCCESS);
			buf_putint(ses.writepayload, allocated_listen_port);
			encrypt_packet();
			wantreply = 0; /* avoid out: below sending another reply */
		}
	} else if (strcmp("cancel-tcpip-forward", reqname) == 0) {
		ret = svr_cancelremotetcp();
#if DROPBEAR_SVR_REMOTESTREAMFWD
	} else if (strcmp("streamlocal-forward@openssh.com", reqname) == 0) {
		ret = svr_remotestreamlocalreq();
	} else if (strcmp("cancel-streamlocal-forward@openssh.com", reqname) == 0) {
		ret = svr_cancelremotestreamlocal();
#endif
	} else {
		TRACE(("reqname isn't tcpip-forward: '%s'", reqname))
	}

out:
	if (wantreply) {
		if (ret == DROPBEAR_SUCCESS) {
			send_msg_request_success();
		} else {
			send_msg_request_failure();
		}
	}

	m_free(reqname);

	TRACE(("leave recv_msg_global_request"))
}

static int matchtcp(const void* typedata1, const void* typedata2) {

	const struct TCPListener *info1 = (struct TCPListener*)typedata1;
	const struct TCPListener *info2 = (struct TCPListener*)typedata2;

	return (info1->listenport == info2->listenport)
			&& (strcmp(info1->request_listenaddr, info2->request_listenaddr) == 0);
}

static int svr_cancelremotetcp() {

	int ret = DROPBEAR_FAILURE;
	char * request_addr = NULL;
	unsigned int addrlen;
	unsigned int port;
	struct Listener * listener = NULL;
	struct TCPListener tcpinfo;

	TRACE(("enter cancelremotetcp"))

	request_addr = buf_getstring(ses.payload, &addrlen);
	if (addrlen > MAX_HOST_LEN) {
		TRACE(("addr len too long: %d", addrlen))
		goto out;
	}

	port = buf_getint(ses.payload);

	memset(&tcpinfo, 0x0, sizeof(tcpinfo));
	tcpinfo.request_listenaddr = request_addr;
	tcpinfo.listenport = port;
	listener = get_listener(LISTENER_TYPE_TCPFORWARDED, &tcpinfo, matchtcp);
	if (listener) {
		remove_listener(listener);
		ret = DROPBEAR_SUCCESS;
	}

out:
	m_free(request_addr);
	TRACE(("leave cancelremotetcp"))
	return ret;
}

static int svr_remotetcpreq(int *allocated_listen_port) {

	int ret = DROPBEAR_FAILURE;
	char * request_addr = NULL;
	unsigned int addrlen;
	struct TCPListener *tcpinfo = NULL;
	unsigned int port;
	struct Listener *listener = NULL;

	TRACE(("enter remotetcpreq"))

	request_addr = buf_getstring(ses.payload, &addrlen);
	if (addrlen > MAX_HOST_LEN) {
		TRACE(("addr len too long: %d", addrlen))
		goto out;
	}

	port = buf_getint(ses.payload);

	if (port != 0) {
		if (port < 1 || port > 65535) {
			TRACE(("invalid port: %d", port))
			goto out;
		}

		if (!ses.allowprivport && port < IPPORT_RESERVED) {
			TRACE(("can't assign port < 1024 for non-root"))
			goto out;
		}
	}

	if (!svr_pubkey_allows_remote_tcpfwd(request_addr, port)) {
		TRACE(("remote tcp forwarding listen address not permitted"));
		goto out;
	}

	tcpinfo = (struct TCPListener*)m_malloc(sizeof(struct TCPListener));
	tcpinfo->sendaddr = NULL;
	tcpinfo->sendport = 0;
	tcpinfo->listenport = port;
	tcpinfo->chantype = &svr_chan_tcpremote;
	tcpinfo->tcp_type = forwarded;
	tcpinfo->interface = svr_opts.interface;

	tcpinfo->request_listenaddr = request_addr;
	if (!opts.listen_fwd_all || (strcmp(request_addr, "localhost") == 0) ) {
		/* NULL means "localhost only" */
		tcpinfo->listenaddr = NULL;
	}
	else
	{
		tcpinfo->listenaddr = m_strdup(request_addr);
	}

	ret = listen_tcpfwd(tcpinfo, &listener);
	if (DROPBEAR_SUCCESS == ret) {
		tcpinfo->listenport = get_sock_port(listener->socks[0]);
		*allocated_listen_port = tcpinfo->listenport;
	}

out:
	if (ret == DROPBEAR_FAILURE) {
		/* we only free it if a listener wasn't created, since the listener
		 * has to remember it if it's to be cancelled */
		m_free(request_addr);
		m_free(tcpinfo);
	}

	TRACE(("leave remotetcpreq"))

	return ret;
}

#if DROPBEAR_SVR_REMOTESTREAMFWD
static int matchstreamlocal(const void* typedata1, const void* typedata2) {

	const struct TCPListener *info1 = (const struct TCPListener*)typedata1;
	const struct TCPListener *info2 = (const struct TCPListener*)typedata2;

	if (info1->socket_path == NULL || info2->socket_path == NULL) {
		return 0;
	}

	return (info1->chantype == info2->chantype)
			&& (strcmp(info1->socket_path, info2->socket_path) == 0);
}

static int svr_cancelremotestreamlocal() {

	int ret = DROPBEAR_FAILURE;
	char * socket_path = NULL;
	unsigned int pathlen;
	struct Listener * listener = NULL;
	struct TCPListener tcpinfo;

	TRACE(("enter cancelremotestreamlocal"))

	socket_path = buf_getstring(ses.payload, &pathlen);
	if (pathlen > MAX_HOST_LEN) {
		TRACE(("path len too long: %d", pathlen))
		goto out;
	}
	if (strlen(socket_path) != pathlen) {
		TRACE(("path has nul byte"));
		goto out;
	}

	tcpinfo.socket_path = socket_path;
	tcpinfo.chantype = &svr_chan_streamlocalremote;
	listener = get_listener(CHANNEL_ID_STREAMLOCALFORWARDED, &tcpinfo, matchstreamlocal);
	if (listener) {
		remove_listener( listener );
		ret = DROPBEAR_SUCCESS;
	}

out:
	m_free(socket_path);
	TRACE(("leave cancelremotestreamlocal"))
	return ret;
}

static void unlink_streamsocket(const char* path) {
	if (unlink(path) < 0 && errno != ENOENT) {
		/* Not fatal */
		DEBUG1(("Failed removing unix socket %s: %s",
			path, strerror(errno)));
	}
}

static void cleanup_streamlocal(const struct Listener *listener) {

	struct TCPListener *tcpinfo = (struct TCPListener*)(listener->typedata);

	if (tcpinfo && tcpinfo->socket_path) {
		unlink_streamsocket(tcpinfo->socket_path);
		m_free(tcpinfo->socket_path);
	}
	m_free(tcpinfo->request_listenaddr);
	m_free(tcpinfo);
}

static void streamlocal_acceptor(const struct Listener *listener, int sock) {

	int fd;
	struct TCPListener *tcpinfo = (struct TCPListener*)(listener->typedata);

	fd = accept(sock, NULL, NULL);
	if (fd < 0) {
		return;
	}

	if (send_msg_channel_open_init(fd, tcpinfo->chantype) == DROPBEAR_SUCCESS) {
		/* "forwarded-streamlocal@openssh.com" */
		/* socket path that was connected to */
		buf_putstring(ses.writepayload, tcpinfo->request_listenaddr,
				strlen(tcpinfo->request_listenaddr));
		/* reserved field */
		buf_putstring(ses.writepayload, "", 0);

		encrypt_packet();

	} else {
		/* XXX debug? */
		close(fd);
	}
}

int listen_streamlocal(struct TCPListener* tcpinfo, struct Listener **ret_listener) {

	int sock, rc, saved_errno;
	struct Listener *listener = NULL;
	struct sockaddr_un addr;
	mode_t old_umask;

	TRACE(("enter listen_streamlocal"))

	if (tcpinfo->socket_path == NULL) {
		TRACE(("leave listen_streamlocal: no socket path"))
		return DROPBEAR_FAILURE;
	}

	if (strlen(tcpinfo->socket_path) >= sizeof(addr.sun_path)) {
		dropbear_log(LOG_INFO, "Streamlocal forward failed: socket path too long");
		TRACE(("leave listen_streamlocal: path too long"))
		return DROPBEAR_FAILURE;
	}

#if DROPBEAR_FUZZ
	if (fuzz.fuzzing) {
		// fuzzing streamlocal is unimplemented
		return DROPBEAR_FAILURE;
	}
#endif

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		dropbear_log(LOG_INFO, "Streamlocal forward failed: socket() failed");
		TRACE(("leave listen_streamlocal: socket() failed"))
		return DROPBEAR_FAILURE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, tcpinfo->socket_path, sizeof(addr.sun_path));

	/* Unlink existing socket if it exists */
	unlink_streamsocket(tcpinfo->socket_path);

	/* Set umask to allow proper permissions on the socket */
	old_umask = umask(0177);
	rc = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
	saved_errno = errno;
	umask(old_umask);

	if (rc < 0) {
		dropbear_log(LOG_INFO, "Streamlocal forward failed: bind() failed: %s", strerror(saved_errno));
		m_close(sock);
		TRACE(("leave listen_streamlocal: bind() failed"))
		return DROPBEAR_FAILURE;
	}


	if (listen(sock, DROPBEAR_LISTEN_BACKLOG) < 0) {
		dropbear_log(LOG_INFO, "Streamlocal forward failed: listen() failed: %s", strerror(errno));
		unlink_streamsocket(tcpinfo->socket_path);
		m_close(sock);
		TRACE(("leave listen_streamlocal: listen() failed"))
		return DROPBEAR_FAILURE;
	}

	setnonblocking(sock);

	listener = new_listener(&sock, 1, LISTENER_TYPE_STREAMFORWARDED, tcpinfo,
			streamlocal_acceptor, cleanup_streamlocal);

	if (listener == NULL) {
		unlink_streamsocket(tcpinfo->socket_path);
		m_close(sock);
		TRACE(("leave listen_streamlocal: listener failed"))
		return DROPBEAR_FAILURE;
	}

	if (ret_listener) {
		*ret_listener = listener;
	}

	TRACE(("leave listen_streamlocal: success"))
	return DROPBEAR_SUCCESS;
}

static int svr_remotestreamlocalreq() {

	int ret = DROPBEAR_FAILURE;
	char * request_path = NULL;
	unsigned int pathlen;
	struct TCPListener *tcpinfo = NULL;
	struct Listener *listener = NULL;

	TRACE(("enter remotestreamlocalreq"))

	if (svr_opts.forced_command || svr_pubkey_has_forced_command()) {
		/* Creating a unix socket in the right place could probably subvert
		 * a forcedcommand, so don't allow that.
		 * This could be relaxed if an authorized_keys "permitlisten"
		 * equivalent were added for streamlocal */
		TRACE(("leave newstreamlocal: no unix forwarding for forced command"))
		goto out;
	}

	if (svr_opts.noremotetcp || !svr_pubkey_allows_tcpfwd()) {
		TRACE(("leave remotestreamlocalreq: remote forwarding disabled"))
		goto out;
	}

	request_path = buf_getstring(ses.payload, &pathlen);
	if (pathlen > MAX_HOST_LEN) {
		TRACE(("path len too long: %d", pathlen))
		goto out;
	}
	if (strlen(request_path) != pathlen) {
		TRACE(("path has nul byte"));
		goto out;
	}

	tcpinfo = (struct TCPListener*)m_malloc(sizeof(struct TCPListener));
	memset(tcpinfo, 0, sizeof(struct TCPListener));
	tcpinfo->sendaddr = NULL;
	tcpinfo->sendport = 0;
	tcpinfo->listenaddr = NULL;
	tcpinfo->listenport = 0;
	tcpinfo->chantype = &svr_chan_streamlocalremote;
	tcpinfo->tcp_type = forwarded;
	tcpinfo->interface = NULL;
	tcpinfo->socket_path = m_strdup(request_path);
	tcpinfo->request_listenaddr = request_path;

	ret = listen_streamlocal(tcpinfo, &listener);

out:
	if (ret == DROPBEAR_FAILURE) {
		/* we only free it if a listener wasn't created, since the listener
		 * has to remember it if it's to be cancelled */
		m_free(request_path);
		m_free(tcpinfo->socket_path);
		m_free(tcpinfo);
	}

	TRACE(("leave remotestreamlocalreq"))
	return ret;
}
#endif /* DROPBEAR_SVR_REMOTESTREAMFWD */

#endif /* DROPBEAR_SVR_REMOTETCPFWD */

#if DROPBEAR_SVR_LOCALTCPFWD

const struct ChanType svr_chan_tcpdirect = {
	"direct-tcpip",
	newtcpdirect, /* init */
	NULL, /* checkclose */
	NULL, /* reqhandler */
	NULL, /* closehandler */
	NULL /* cleanup */
};

/* Called upon creating a new direct tcp channel (ie we connect out to an
 * address */
static int newtcpdirect(struct Channel * channel) {

	char* desthost = NULL;
	unsigned int destport;
	char* orighost = NULL;
	unsigned int origport;
	char portstring[NI_MAXSERV];
	unsigned int len;
	int err = SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;

	TRACE(("newtcpdirect channel %d", channel->index))

	if (svr_opts.nolocaltcp || !svr_pubkey_allows_tcpfwd()) {
		TRACE(("leave newtcpdirect: local tcp forwarding disabled"))
		goto out;
	}

	desthost = buf_getstring(ses.payload, &len);
	if (len > MAX_HOST_LEN) {
		TRACE(("leave newtcpdirect: desthost too long"))
		goto out;
	}

	destport = buf_getint(ses.payload);
	
	orighost = buf_getstring(ses.payload, &len);
	if (len > MAX_HOST_LEN) {
		TRACE(("leave newtcpdirect: orighost too long"))
		goto out;
	}

	origport = buf_getint(ses.payload);

	/* best be sure */
	if (origport > 65535 || destport > 65535) {
		TRACE(("leave newtcpdirect: port > 65535"))
		goto out;
	}

	if (!svr_pubkey_allows_local_tcpfwd(desthost, destport)) {
		TRACE(("leave newtcpdirect: local tcp forwarding not permitted to requested destination"));
		goto out;
	}

	snprintf(portstring, sizeof(portstring), "%u", destport);
	channel->conn_pending = connect_remote(desthost, portstring, channel_connect_done,
		channel, NULL, NULL, DROPBEAR_PRIO_NORMAL);

	err = SSH_OPEN_IN_PROGRESS;

out:
	m_free(desthost);
	m_free(orighost);
	TRACE(("leave newtcpdirect: err %d", err))
	return err;
}

#endif /* DROPBEAR_SVR_LOCALTCPFWD */


#if DROPBEAR_SVR_LOCALSTREAMFWD

const struct ChanType svr_chan_streamlocal = {
	"direct-streamlocal@openssh.com",
	newstreamlocal, /* init */
	NULL, /* checkclose */
	NULL, /* reqhandler */
	NULL, /* closehandler */
	NULL /* cleanup */
};

/* Called upon creating a new stream local channel (ie we connect out to an
 * address */
static int newstreamlocal(struct Channel * channel) {

	/*
	https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL#rev1.30

	byte		SSH_MSG_CHANNEL_OPEN
	string		"direct-streamlocal@openssh.com"
	uint32		sender channel
	uint32		initial window size
	uint32		maximum packet size
	string		socket path
	string		reserved
	uint32		reserved
	*/

	char* destsocket = NULL;
	unsigned int len;
	int err = SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;

	TRACE(("streamlocal channel %d", channel->index))

	if (svr_opts.forced_command || svr_pubkey_has_forced_command()) {
		TRACE(("leave newstreamlocal: no unix forwarding for forced command"))
		goto out;
	}

	if (svr_opts.nolocaltcp || !svr_pubkey_allows_tcpfwd()) {
		TRACE(("leave newstreamlocal: local unix forwarding disabled"))
		goto out;
	}

	destsocket = buf_getstring(ses.payload, &len);
	if (len > MAX_HOST_LEN) {
		TRACE(("leave streamlocal: destsocket too long"))
		goto out;
	}

	channel->conn_pending = connect_streamlocal(destsocket, channel_connect_done,
		channel, DROPBEAR_PRIO_NORMAL);

	err = SSH_OPEN_IN_PROGRESS;

out:
	m_free(destsocket);
	TRACE(("leave streamlocal: err %d", err))
	return err;
}

#endif /* DROPBEAR_SVR_LOCALSTREAMFWD */
