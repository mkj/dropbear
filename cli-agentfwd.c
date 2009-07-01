/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2005 Matt Johnston
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

/* The basic protocol use to communicate with the agent is defined in
 * draft-ylonen-ssh-protocol-00.txt, with the ssh2 extensions defined through
 * openssh's implementation. */

#include "includes.h"

#ifdef ENABLE_CLI_AGENTFWD

#include "agentfwd.h"
#include "session.h"
#include "ssh.h"
#include "dbutil.h"
#include "chansession.h"
#include "channel.h"
#include "packet.h"
#include "buffer.h"
#include "random.h"
#include "listener.h"
#include "runopts.h"
#include "atomicio.h"
#include "signkey.h"
#include "auth.h"

static int new_agent_chan(struct Channel * channel);

const struct ChanType cli_chan_agent = {
	0, /* sepfds */
	"auth-agent@openssh.com",
	new_agent_chan,
	NULL,
	NULL,
	NULL
};

static int connect_agent() {

	int fd = -1;
	char* agent_sock = NULL;

	agent_sock = getenv("SSH_AUTH_SOCK");
	if (agent_sock == NULL)
		return -1;

	fd = connect_unix(agent_sock);

	return fd;
}

// handle a request for a connection to the locally running ssh-agent
// or forward.
static int new_agent_chan(struct Channel * channel) {

	int fd = -1;

	if (!cli_opts.agent_fwd)
		return SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;

	fd = connect_agent();

	setnonblocking(fd);

	ses.maxfd = MAX(ses.maxfd, fd);

	channel->readfd = fd;
	channel->writefd = fd;

	// success
	return 0;
}

/* Sends a request to the agent, returning a newly allocated buffer
 * with the response */
/* This function will block waiting for a response - it will
 * only be used by client authentication (not for forwarded requests)
 * won't cause problems for interactivity. */
/* Packet format (from draft-ylonen)
   4 bytes     Length, msb first.  Does not include length itself.
   1 byte      Packet type.  The value 255 is reserved for future extensions.
   data        Any data, depending on packet type.  Encoding as in the ssh packet
               protocol.
*/
static buffer * agent_request(int fd, unsigned char type) {

	buffer * payload = NULL;
	buffer * inbuf = NULL;
	size_t readlen = 0;
	ssize_t ret;

	payload = buf_new(4 + 1);

	buf_putint(payload, 1);
	buf_putbyte(payload, type);
	buf_setpos(payload, 0);

	ret = atomicio(write, fd, buf_getptr(payload, payload->len), payload->len);
	if ((size_t)ret != payload->len) {
		TRACE(("write failed fd %d for agent_request, %s", fd, strerror(errno)))
		goto out;
	}

	buf_free(payload);
	payload = NULL;
	TRACE(("Wrote out bytes for agent_request"))
	/* Now we read the response */
	inbuf = buf_new(4);
	ret = atomicio(read, fd, buf_getwriteptr(inbuf, 4), 4);
	if (ret != 4) {
		TRACE(("read of length failed for agent_request"))
		goto out;
	}
	buf_setpos(inbuf, 0);
	buf_setlen(inbuf, ret);

	readlen = buf_getint(inbuf);
	if (readlen > MAX_AGENT_REPLY) {
		TRACE(("agent reply is too big"));
		goto out;
	}
	
	TRACE(("agent_request readlen is %d", readlen))

	buf_resize(inbuf, readlen);
	buf_setpos(inbuf, 0);
	ret = atomicio(read, fd, buf_getwriteptr(inbuf, readlen), readlen);
	if ((size_t)ret != readlen) {
		TRACE(("read of data failed for agent_request"))
		goto out;
	}
	buf_incrwritepos(inbuf, readlen);
	buf_setpos(inbuf, 0);
	TRACE(("agent_request success, length %d", readlen))

out:
	if (payload)
		buf_free(payload);

	return inbuf;
}

static void agent_get_key_list(int fd, struct SignKeyList * ret_list)
{
	buffer * inbuf = NULL;
	unsigned int num = 0;
	unsigned char packet_type;
	unsigned int i;
	struct SignKeyList *key = NULL;
	int ret;

	inbuf = agent_request(fd, SSH2_AGENTC_REQUEST_IDENTITIES);
	if (!inbuf) {
		TRACE(("agent_request returned no identities"))
		goto out;
	}

	/* The reply has a format of:
	 * byte     packet_type
	 * int      num_keys
	 *
	 * string    keyblob1
	 * string    comment1
	 * ...
	 * string    keyblob(n)
	 * string    comment(n)
	 */
	packet_type = buf_getbyte(inbuf);
	if (packet_type != SSH2_AGENT_IDENTITIES_ANSWER) {
		goto out;
	}

	num = buf_getint(inbuf);
	for (i = 0; i < num; i++) {
		sign_key * pubkey = NULL;
		int key_type = DROPBEAR_SIGNKEY_ANY;
		struct SignKeyList *nextkey = NULL;

		nextkey = (struct SignKeyList*)m_malloc(sizeof(struct SignKeyList));
		ret_list->next = nextkey;
		ret_list = nextkey;

		pubkey = new_sign_key();
		ret = buf_get_pub_key(inbuf, pubkey, &key_type);
		if (ret != DROPBEAR_SUCCESS) {
			/* This is slack, properly would cleanup vars etc */
			dropbear_exit("Bad pubkey received from agent");
		}

		key->key = pubkey;
		key->next = NULL;
		key->type = key_type;
		key->source = SIGNKEY_SOURCE_AGENT;

		/* We'll ignore the comment */
		buf_eatstring(inbuf);
	}

out:
	if (inbuf) {
		buf_free(inbuf);
		inbuf = NULL;
	}
}

/* Returned keys are appended to ret_list */
void load_agent_keys(struct SignKeyList * ret_list)
{
	int fd;
	fd = connect_agent();
	if (fd < 0) {
		dropbear_log(LOG_INFO, "Failed to connect to agent");
		return;
	}

	agent_get_key_list(fd, ret_list);
	close(fd);
}
	
// general procedure:
// - get the list of keys from the agent
// - foreach, send a dummy userauth_pubkey message to the server and see
// if it lets us in
// - if it does, sign and auth
// - if not, repeat.
//

#endif
