/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
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

/* This file (agentfwd.c) handles authentication agent forwarding, for OpenSSH
 * style agents. */

#include "includes.h"

#ifndef DISABLE_AGENTFWD

#include "agentfwd.h"
#include "session.h"
#include "ssh.h"
#include "dbutil.h"
#include "chansession.h"
#include "channel.h"
#include "packet.h"
#include "buffer.h"
#include "random.h"

#define AGENTDIRPREFIX "/tmp/dropbear-"

static int send_msg_channel_open_agent(int fd);
static int bindagent(struct ChanSess * chansess);

/* Handles client requests to start agent forwarding, sets up listening socket.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int agentreq(struct ChanSess * chansess) {

	if (chansess->agentfd != -1) {
		return DROPBEAR_FAILURE;
	}

	/* create listening socket */
	chansess->agentfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (chansess->agentfd < 0) {
		goto fail;
	}

	/* create the unix socket dir and file */
	if (bindagent(chansess) == DROPBEAR_FAILURE) {
		return DROPBEAR_FAILURE;
	}

	/* listen */
	if (listen(chansess->agentfd, 20) < 0) {
		goto fail;
	}

	/* set non-blocking */
	if (fcntl(chansess->agentfd, F_SETFL, O_NONBLOCK) < 0) {
		goto fail;
	}

	/* channel.c's channel fd code will handle the socket now */

	/* set the maxfd so that select() loop will notice it */
	ses.maxfd = MAX(ses.maxfd, chansess->agentfd);

	return DROPBEAR_SUCCESS;

fail:
	/* cleanup */
	agentcleanup(chansess);

	return DROPBEAR_FAILURE;
}

/* accepts a connection on the forwarded socket and opens a new channel for it
 * back to the client */
/* returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int agentaccept(struct ChanSess * chansess) {

	int fd;

	fd = accept(chansess->agentfd, NULL, NULL);
	if (fd < 0) {
		return DROPBEAR_FAILURE;
	}

	return send_msg_channel_open_agent(fd);

}

/* set up the environment variable pointing to the socket. This is called
 * just before command/shell execution, after dropping priveleges */
void agentset(struct ChanSess * chansess) {

	char path[MAXPATHLEN];

	if (chansess->agentfd == -1) {
		return;
	}

	snprintf(path, sizeof(path), "%s/%s", chansess->agentdir,
			chansess->agentfile);
	addnewvar("SSH_AUTH_SOCK", path);
}

/* close the socket, remove the socket-file */
void agentcleanup(struct ChanSess * chansess) {

	char path[MAXPATHLEN];
	uid_t uid;
	gid_t gid;

	if (chansess->agentfd == -1) {
		return;
	}

	close(chansess->agentfd);

	/* Remove the dir as the user. That way they can't cause problems except
	 * for themselves */
	uid = getuid();
	gid = getgid();
	if ((setegid(ses.authstate.pw->pw_gid)) < 0 ||
		(seteuid(ses.authstate.pw->pw_uid)) < 0) {
		dropbear_exit("failed to set euid");
	}

	snprintf(path, sizeof(path),
			"%s/%s", chansess->agentdir, chansess->agentfile);

	unlink(path);
	rmdir(chansess->agentdir);

	if ((seteuid(uid)) < 0 ||
		(setegid(gid)) < 0) {
		dropbear_exit("failed to revert euid");
	}

	m_free(chansess->agentfile);
	m_free(chansess->agentdir);

}

/* helper for accepting an agent request */
static int send_msg_channel_open_agent(int fd) {

	if (send_msg_channel_open_init(fd, "auth-agent@openssh.com") 
			== DROPBEAR_SUCCESS) {
		encrypt_packet();
		return DROPBEAR_SUCCESS;
	} else {
		return DROPBEAR_FAILURE;
	}
}

/* helper for creating the agent socket-file
   returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int bindagent(struct ChanSess * chansess) {

	struct sockaddr_un addr;
	unsigned int prefix;
	char path[sizeof(addr.sun_path)], sockfile[sizeof(addr.sun_path)];
	mode_t mode;
	int i;
	uid_t uid;
	gid_t gid;
	int ret = DROPBEAR_FAILURE;

	/* drop to user privs to make the dir/file */
	uid = getuid();
	gid = getgid();
	if ((setegid(ses.authstate.pw->pw_gid)) < 0 ||
		(seteuid(ses.authstate.pw->pw_uid)) < 0) {
		dropbear_exit("failed to set euid");
	}

	memset((void*)&addr, 0x0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	mode = S_IRWXU;

	for (i = 0; i < 20; i++) {
		genrandom((unsigned char*)&prefix, sizeof(prefix));
		/* we want 32 bits (8 hex digits) - "/tmp/dropbear-f19c62c0" */
		snprintf(path, sizeof(path), AGENTDIRPREFIX "%.8x", prefix);

		if (mkdir(path, mode) == 0) {
			goto bindsocket;
		}
		if (errno != EEXIST) {
			break;
		}
	}
	/* couldn't make a dir */
	goto out;

bindsocket:
	/* Format is "/tmp/dropbear-0246dead/auth-d00f7654-23".
	 * The "23" is the file desc, the random data is to avoid collisions
	 * between subsequent user processes reusing socket fds (odds are now
	 * 1/(2^64) */
	genrandom((unsigned char*)&prefix, sizeof(prefix));
	snprintf(sockfile, sizeof(sockfile), "auth-%.8x-%d", prefix,
			chansess->agentfd);
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", path, sockfile);

	if (bind(chansess->agentfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
		chansess->agentdir = strdup(path);
		chansess->agentfile = strdup(sockfile);
		ret = DROPBEAR_SUCCESS;
	}


out:
	if ((seteuid(uid)) < 0 ||
		(setegid(gid)) < 0) {
		dropbear_exit("failed to revert euid");
	}
	return ret;
}

#endif
