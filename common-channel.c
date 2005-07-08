/*
 * Dropbear SSH
 * 
 * Copyright (c) 2002-2004 Matt Johnston
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

/* Handle the multiplexed channels, such as sessions, x11, agent connections */

#include "includes.h"
#include "session.h"
#include "packet.h"
#include "ssh.h"
#include "buffer.h"
#include "circbuffer.h"
#include "dbutil.h"
#include "channel.h"
#include "ssh.h"
#include "listener.h"

static void send_msg_channel_open_failure(unsigned int remotechan, int reason,
		const unsigned char *text, const unsigned char *lang);
static void send_msg_channel_open_confirmation(struct Channel* channel,
		unsigned int recvwindow, 
		unsigned int recvmaxpacket);
static void writechannel(struct Channel* channel, int fd, circbuffer *cbuf);
static void send_msg_channel_window_adjust(struct Channel *channel, 
		unsigned int incr);
static void send_msg_channel_data(struct Channel *channel, int isextended,
		unsigned int exttype);
static void send_msg_channel_eof(struct Channel *channel);
static void send_msg_channel_close(struct Channel *channel);
static void removechannel(struct Channel *channel);
static void deletechannel(struct Channel *channel);
static void checkinitdone(struct Channel *channel);
static void checkclose(struct Channel *channel);

static void closeinfd(struct Channel * channel);
static void closeoutfd(struct Channel * channel, int fd);
static void closechanfd(struct Channel *channel, int fd, int how);

#define FD_UNINIT (-2)
#define FD_CLOSED (-1)

/* Initialise all the channels */
void chaninitialise(const struct ChanType *chantypes[]) {

	/* may as well create space for a single channel */
	ses.channels = (struct Channel**)m_malloc(sizeof(struct Channel*));
	ses.chansize = 1;
	ses.channels[0] = NULL;
	ses.chancount = 0;

	ses.chantypes = chantypes;

#ifdef USING_LISTENERS
	listeners_initialise();
#endif

}

/* Clean up channels, freeing allocated memory */
void chancleanup() {

	unsigned int i;

	TRACE(("enter chancleanup"))
	for (i = 0; i < ses.chansize; i++) {
		if (ses.channels[i] != NULL) {
			TRACE(("channel %d closing", i))
			removechannel(ses.channels[i]);
		}
	}
	m_free(ses.channels);
	TRACE(("leave chancleanup"))
}

/* Create a new channel entry, send a reply confirm or failure */
/* If remotechan, transwindow and transmaxpacket are not know (for a new
 * outgoing connection, with them to be filled on confirmation), they should
 * all be set to 0 */
struct Channel* newchannel(unsigned int remotechan, 
		const struct ChanType *type, 
		unsigned int transwindow, unsigned int transmaxpacket) {

	struct Channel * newchan;
	unsigned int i, j;

	TRACE(("enter newchannel"))
	
	/* first see if we can use existing channels */
	for (i = 0; i < ses.chansize; i++) {
		if (ses.channels[i] == NULL) {
			break;
		}
	}

	/* otherwise extend the list */
	if (i == ses.chansize) {
		if (ses.chansize >= MAX_CHANNELS) {
			TRACE(("leave newchannel: max chans reached"))
			return NULL;
		}

		/* extend the channels */
		ses.channels = (struct Channel**)m_realloc(ses.channels,
				(ses.chansize+CHAN_EXTEND_SIZE)*sizeof(struct Channel*));

		ses.chansize += CHAN_EXTEND_SIZE;

		/* set the new channels to null */
		for (j = i; j < ses.chansize; j++) {
			ses.channels[j] = NULL;
		}

	}
	
	newchan = (struct Channel*)m_malloc(sizeof(struct Channel));
	newchan->type = type;
	newchan->index = i;
	newchan->sentclosed = newchan->recvclosed = 0;
	newchan->senteof = newchan->recveof = 0;

	newchan->remotechan = remotechan;
	newchan->transwindow = transwindow;
	newchan->transmaxpacket = transmaxpacket;
	
	newchan->typedata = NULL;
	newchan->infd = FD_UNINIT;
	newchan->outfd = FD_UNINIT;
	newchan->errfd = FD_CLOSED; /* this isn't always set to start with */
	newchan->initconn = 0;

	newchan->writebuf = cbuf_new(RECV_MAXWINDOW);
	newchan->extrabuf = NULL; /* The user code can set it up */
	newchan->recvwindow = RECV_MAXWINDOW;
	newchan->recvdonelen = 0;
	newchan->recvmaxpacket = RECV_MAXPACKET;

	ses.channels[i] = newchan;
	ses.chancount++;

	TRACE(("leave newchannel"))

	return newchan;
}

/* Returns the channel structure corresponding to the channel in the current
 * data packet (ses.payload must be positioned appropriately) */
struct Channel* getchannel() {

	unsigned int chan;

	chan = buf_getint(ses.payload);
	if (chan >= ses.chansize || ses.channels[chan] == NULL) {
		return NULL;
	}
	return ses.channels[chan];
}

/* Iterate through the channels, performing IO if available */
void channelio(fd_set *readfd, fd_set *writefd) {

	struct Channel *channel;
	unsigned int i;
	int ret;

	/* iterate through all the possible channels */
	for (i = 0; i < ses.chansize; i++) {

		channel = ses.channels[i];
		if (channel == NULL) {
			/* only process in-use channels */
			continue;
		}

		/* read from program/pipe stdout */
		if (channel->outfd >= 0 && FD_ISSET(channel->outfd, readfd)) {
			send_msg_channel_data(channel, 0, 0);
		}

		/* read from program/pipe stderr */
		if (channel->extrabuf == NULL &&
				channel->errfd >= 0 && FD_ISSET(channel->errfd, readfd)) {
				send_msg_channel_data(channel, 1, SSH_EXTENDED_DATA_STDERR);
		}

		/* if we can read from the infd, it might be closed, so we try to
		 * see if it has errors */
		if (channel->infd >= 0 && channel->infd != channel->outfd
				&& FD_ISSET(channel->infd, readfd)) {
			if (channel->initconn) {
				/* Handling for "in progress" connection - this is needed
				 * to avoid spinning 100% CPU when we connect to a server
				 * which doesn't send anything (tcpfwding) */
				checkinitdone(channel);
				continue; /* Important not to use the channel after 
							 checkinitdone(), as it may be NULL */
			}
			ret = write(channel->infd, NULL, 0); /* Fake write */
			if (ret < 0 && errno != EINTR && errno != EAGAIN) {
				closeinfd(channel);
			}
		}

		/* write to program/pipe stdin */
		if (channel->infd >= 0 && FD_ISSET(channel->infd, writefd)) {
			if (channel->initconn) {
				checkinitdone(channel);
				continue; /* Important not to use the channel after
							 checkinitdone(), as it may be NULL */
			}
			writechannel(channel, channel->infd, channel->writebuf);
		}
		
		/* stderr for client mode */
		if (channel->extrabuf != NULL 
				&& channel->errfd >= 0 && FD_ISSET(channel->errfd, writefd)) {
			writechannel(channel, channel->errfd, channel->extrabuf);
		}
	
		/* now handle any of the channel-closing type stuff */
		checkclose(channel);

	} /* foreach channel */

	/* Listeners such as TCP, X11, agent-auth */
#ifdef USING_LISTENERS
	handle_listeners(readfd);
#endif
}


/* do all the EOF/close type stuff checking for a channel */
static void checkclose(struct Channel *channel) {

	TRACE(("checkclose: infd %d, outfd %d, errfd %d, sentclosed %d, recvclosed %d",
				channel->infd, channel->outfd,
				channel->errfd, channel->sentclosed, channel->recvclosed))
	TRACE(("writebuf %d extrabuf %s extrabuf %d",
				cbuf_getused(channel->writebuf),
				channel->writebuf,
				channel->writebuf ? 0 : cbuf_getused(channel->extrabuf)))

	if (!channel->sentclosed) {

		/* check for exited - currently only used for server sessions,
		 * if the shell has exited etc */
		if (channel->type->checkclose) {
			if (channel->type->checkclose(channel)) {
				closeinfd(channel);
			}
		}

		if (!channel->senteof
			&& channel->outfd == FD_CLOSED 
			&& (channel->extrabuf != NULL || channel->errfd == FD_CLOSED)) {
			send_msg_channel_eof(channel);
		}

		if (channel->infd == FD_CLOSED
			&& channel->outfd == FD_CLOSED
			&& (channel->extrabuf != NULL || channel->errfd == FD_CLOSED)) {
			send_msg_channel_close(channel);
		}
	}

	/* When either party wishes to terminate the channel, it sends
	 * SSH_MSG_CHANNEL_CLOSE.  Upon receiving this message, a party MUST
	 * send back a SSH_MSG_CHANNEL_CLOSE unless it has already sent this
	 * message for the channel.  The channel is considered closed for a
	 * party when it has both sent and received SSH_MSG_CHANNEL_CLOSE, and
	 * the party may then reuse the channel number.  A party MAY send
	 * SSH_MSG_CHANNEL_CLOSE without having sent or received
	 * SSH_MSG_CHANNEL_EOF. 
	 * (from draft-ietf-secsh-connect)
	 */
	if (channel->recvclosed) {
		if (! channel->sentclosed) {
			TRACE(("Sending MSG_CHANNEL_CLOSE in response to same."))
			send_msg_channel_close(channel);
		}
		removechannel(channel);
	}
}


/* Check whether a deferred (EINPROGRESS) connect() was successful, and
 * if so, set up the channel properly. Otherwise, the channel is cleaned up, so
 * it is important that the channel reference isn't used after a call to this
 * function */
static void checkinitdone(struct Channel *channel) {

	int val;
	socklen_t vallen = sizeof(val);

	TRACE(("enter checkinitdone"))

	if (getsockopt(channel->infd, SOL_SOCKET, SO_ERROR, &val, &vallen)
			|| val != 0) {
		send_msg_channel_open_failure(channel->remotechan,
				SSH_OPEN_CONNECT_FAILED, "", "");
		close(channel->infd);
		deletechannel(channel);
		TRACE(("leave checkinitdone: fail"))
	} else {
		send_msg_channel_open_confirmation(channel, channel->recvwindow,
				channel->recvmaxpacket);
		channel->outfd = channel->infd;
		channel->initconn = 0;
		TRACE(("leave checkinitdone: success"))
	}
}



/* Send the close message and set the channel as closed */
static void send_msg_channel_close(struct Channel *channel) {

	TRACE(("enter send_msg_channel_close"))
	/* XXX server */
	if (channel->type->closehandler) {
		channel->type->closehandler(channel);
	}
	
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_CLOSE);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();

	channel->senteof = 1;
	channel->sentclosed = 1;
	TRACE(("leave send_msg_channel_close"))
}

/* call this when trans/eof channels are closed */
static void send_msg_channel_eof(struct Channel *channel) {

	TRACE(("enter send_msg_channel_eof"))
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_EOF);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();

	channel->senteof = 1;

	TRACE(("leave send_msg_channel_eof"))
}

/* Called to write data out to the local side of the channel. 
 * Only called when we know we can write to a channel, writes as much as
 * possible */
static void writechannel(struct Channel* channel, int fd, circbuffer *cbuf) {

	int len, maxlen;

	TRACE(("enter writechannel"))

	maxlen = cbuf_readlen(cbuf);

	/* Write the data out */
	len = write(fd, cbuf_readptr(cbuf, maxlen), maxlen);
	if (len <= 0) {
		if (len < 0 && errno != EINTR) {
			/* no more to write - we close it even if the fd was stderr, since
			 * that's a nasty failure too */
			closeinfd(channel);
		}
		TRACE(("leave writechannel: len <= 0"))
		return;
	}

	cbuf_incrread(cbuf, len);
	channel->recvdonelen += len;

	if (fd == channel->infd && len == maxlen && channel->recveof) { 
		/* Check if we're closing up */
		closeinfd(channel);
		TRACE(("leave writechannel: recveof set"))
		return;
	}

	/* Window adjust handling */
	if (channel->recvdonelen >= RECV_WINDOWEXTEND) {
		/* Set it back to max window */
		send_msg_channel_window_adjust(channel, channel->recvdonelen);
		channel->recvwindow += channel->recvdonelen;
		channel->recvdonelen = 0;
	}

	assert(channel->recvwindow <= RECV_MAXWINDOW);
	assert(channel->recvwindow <= cbuf_getavail(channel->writebuf));
	assert(channel->extrabuf == NULL ||
			channel->recvwindow <= cbuf_getavail(channel->extrabuf));
	
	
	TRACE(("leave writechannel"))
}

/* Set the file descriptors for the main select in session.c
 * This avoid channels which don't have any window available, are closed, etc*/
void setchannelfds(fd_set *readfd, fd_set *writefd) {
	
	unsigned int i;
	struct Channel * channel;
	
	for (i = 0; i < ses.chansize; i++) {

		channel = ses.channels[i];
		if (channel == NULL) {
			continue;
		}

		/* Stuff to put over the wire */
		if (channel->transwindow > 0) {

			if (channel->outfd >= 0) {
				FD_SET(channel->outfd, readfd);
			}
			
			if (channel->extrabuf == NULL && channel->errfd >= 0) {
					FD_SET(channel->errfd, readfd);
			}
		}

		/* For checking FD status (ie closure etc) - we don't actually
		 * read data from infd */
		TRACE(("infd = %d, outfd %d, errfd %d, bufused %d", 
					channel->infd, channel->outfd,
					channel->errfd,
					cbuf_getused(channel->writebuf) ))
		if (channel->infd >= 0 && channel->infd != channel->outfd) {
			FD_SET(channel->infd, readfd);
		}

		/* Stuff from the wire, to local program/shell/user etc */
		if ((channel->infd >= 0 && cbuf_getused(channel->writebuf) > 0 )
				|| channel->initconn) {

				FD_SET(channel->infd, writefd);
		}

		if (channel->extrabuf != NULL && channel->errfd >= 0 
				&& cbuf_getused(channel->extrabuf) > 0 ) {
				FD_SET(channel->errfd, writefd);
		}

	} /* foreach channel */

#ifdef USING_LISTENERS
	set_listener_fds(readfd);
#endif

}

/* handle the channel EOF event, by closing the channel filedescriptor. The
 * channel isn't closed yet, it is left until the incoming (from the program
 * etc) FD is also EOF */
void recv_msg_channel_eof() {

	struct Channel * channel;

	TRACE(("enter recv_msg_channel_eof"))

	channel = getchannel();
	if (channel == NULL) {
		dropbear_exit("EOF for unknown channel");
	}

	channel->recveof = 1;
	if (cbuf_getused(channel->writebuf) == 0
			&& (channel->extrabuf == NULL 
					|| cbuf_getused(channel->extrabuf) == 0)) {
		closeinfd(channel);
	}

	TRACE(("leave recv_msg_channel_eof"))
}


/* Handle channel closure(), respond in kind and close the channels */
void recv_msg_channel_close() {

	struct Channel * channel;

	TRACE(("enter recv_msg_channel_close"))

	channel = getchannel();
	if (channel == NULL) {
		/* disconnect ? */
		dropbear_exit("Close for unknown channel");
	}

	channel->recveof = 1;
	channel->recvclosed = 1;

	if (channel->sentclosed) {
		removechannel(channel);
	}

	TRACE(("leave recv_msg_channel_close"))
}

/* Remove a channel entry, this is only executed after both sides have sent
 * channel close */
static void removechannel(struct Channel * channel) {

	TRACE(("enter removechannel"))
	TRACE(("channel index is %d", channel->index))

	cbuf_free(channel->writebuf);
	channel->writebuf = NULL;

	if (channel->extrabuf) {
		cbuf_free(channel->extrabuf);
		channel->extrabuf = NULL;
	}


	/* close the FDs in case they haven't been done
	 * yet (ie they were shutdown etc */
	close(channel->infd);
	close(channel->outfd);
	close(channel->errfd);

	channel->typedata = NULL;

	deletechannel(channel);

	TRACE(("leave removechannel"))
}

/* Remove a channel entry */
static void deletechannel(struct Channel *channel) {

	ses.channels[channel->index] = NULL;
	m_free(channel);
	ses.chancount--;
	
}


/* Handle channel specific requests, passing off to corresponding handlers
 * such as chansession or x11fwd */
void recv_msg_channel_request() {

	struct Channel *channel;

	TRACE(("enter recv_msg_channel_request"))
	
	channel = getchannel();
	if (channel == NULL) {
		/* disconnect ? */
		dropbear_exit("Unknown channel");
	}

	if (channel->type->reqhandler) {
		channel->type->reqhandler(channel);
	} else {
		send_msg_channel_failure(channel);
	}

	TRACE(("leave recv_msg_channel_request"))

}

/* Reads data from the server's program/shell/etc, and puts it in a
 * channel_data packet to send.
 * chan is the remote channel, isextended is 0 if it is normal data, 1
 * if it is extended data. if it is extended, then the type is in
 * exttype */
static void send_msg_channel_data(struct Channel *channel, int isextended,
		unsigned int exttype) {

	buffer *buf;
	int len;
	unsigned int maxlen;
	int fd;

/*	TRACE(("enter send_msg_channel_data"))
	TRACE(("extended = %d type = %d", isextended, exttype))*/

	CHECKCLEARTOWRITE();

	assert(!channel->sentclosed);

	if (isextended) {
		fd = channel->errfd;
	} else {
		fd = channel->outfd;
	}
	assert(fd >= 0);

	maxlen = MIN(channel->transwindow, channel->transmaxpacket);
	/* -(1+4+4) is SSH_MSG_CHANNEL_DATA, channel number, string length, and 
	 * exttype if is extended */
	maxlen = MIN(maxlen, 
			ses.writepayload->size - 1 - 4 - 4 - (isextended ? 4 : 0));
	if (maxlen == 0) {
		TRACE(("leave send_msg_channel_data: no window"))
		return; /* the data will get written later */
	}

	/* read the data */
	TRACE(("maxlen %d", maxlen))
	buf = buf_new(maxlen);
	TRACE(("buf pos %d data %x", buf->pos, buf->data))
	len = read(fd, buf_getwriteptr(buf, maxlen), maxlen);
	if (len <= 0) {
		/* on error/eof, send eof */
		if (len == 0 || errno != EINTR) {
			closeoutfd(channel, fd);
		}
		buf_free(buf);
		buf = NULL;
		TRACE(("leave send_msg_channel_data: read err or EOF for fd %d", 
					channel->index));
		return;
	}
	buf_incrlen(buf, len);

	buf_putbyte(ses.writepayload, 
			isextended ? SSH_MSG_CHANNEL_EXTENDED_DATA : SSH_MSG_CHANNEL_DATA);
	buf_putint(ses.writepayload, channel->remotechan);

	if (isextended) {
		buf_putint(ses.writepayload, exttype);
	}

	buf_putstring(ses.writepayload, buf_getptr(buf, len), len);
	buf_free(buf);
	buf = NULL;

	channel->transwindow -= len;

	encrypt_packet();
	TRACE(("leave send_msg_channel_data"))
}

/* We receive channel data */
void recv_msg_channel_data() {

	struct Channel *channel;

	channel = getchannel();
	if (channel == NULL) {
		dropbear_exit("Unknown channel");
	}

	common_recv_msg_channel_data(channel, channel->infd, channel->writebuf);
}

/* Shared for data and stderr data - when we receive data, put it in a buffer
 * for writing to the local file descriptor */
void common_recv_msg_channel_data(struct Channel *channel, int fd, 
		circbuffer * cbuf) {

	unsigned int datalen;
	unsigned int maxdata;
	unsigned int buflen;
	unsigned int len;

	TRACE(("enter recv_msg_channel_data"))

	if (channel->recveof) {
		dropbear_exit("received data after eof");
	}

 	if (fd < 0) {
		dropbear_exit("received data with bad infd");
	}

	datalen = buf_getint(ses.payload);


	maxdata = cbuf_getavail(cbuf);

	/* Whilst the spec says we "MAY ignore data past the end" this could
	 * lead to corrupted file transfers etc (chunks missed etc). It's better to
	 * just die horribly */
	if (datalen > maxdata) {
		dropbear_exit("Oversized packet");
	}

	/* We may have to run throught twice, if the buffer wraps around. Can't
	 * just "leave it for next time" like with writechannel, since this
	 * is payload data */
	len = datalen;
	while (len > 0) {
		buflen = cbuf_writelen(cbuf);
		buflen = MIN(buflen, len);

		memcpy(cbuf_writeptr(cbuf, buflen), 
				buf_getptr(ses.payload, buflen), buflen);
		cbuf_incrwrite(cbuf, buflen);
		buf_incrpos(ses.payload, buflen);
		len -= buflen;
	}

	assert(channel->recvwindow >= datalen);
	channel->recvwindow -= datalen;
	assert(channel->recvwindow <= RECV_MAXWINDOW);

	TRACE(("leave recv_msg_channel_data"))
}

/* Increment the outgoing data window for a channel - the remote end limits
 * the amount of data which may be transmitted, this window is decremented
 * as data is sent, and incremented upon receiving window-adjust messages */
void recv_msg_channel_window_adjust() {

	struct Channel * channel;
	unsigned int incr;
	
	channel = getchannel();
	if (channel == NULL) {
		dropbear_exit("Unknown channel");
	}
	
	incr = buf_getint(ses.payload);
	TRACE(("received window increment %d", incr))
	incr = MIN(incr, MAX_TRANS_WIN_INCR);
	
	channel->transwindow += incr;
	channel->transwindow = MIN(channel->transwindow, MAX_TRANS_WINDOW);

}

/* Increment the incoming data window for a channel, and let the remote
 * end know */
static void send_msg_channel_window_adjust(struct Channel* channel, 
		unsigned int incr) {

	TRACE(("sending window adjust %d", incr))
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_WINDOW_ADJUST);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putint(ses.writepayload, incr);

	encrypt_packet();
}
	
/* Handle a new channel request, performing any channel-type-specific setup */
/* XXX server */
void recv_msg_channel_open() {

	unsigned char *type;
	unsigned int typelen;
	unsigned int remotechan, transwindow, transmaxpacket;
	struct Channel *channel;
	const struct ChanType **cp;
	const struct ChanType *chantype;
	unsigned int errtype = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;
	int ret;


	TRACE(("enter recv_msg_channel_open"))

	/* get the packet contents */
	type = buf_getstring(ses.payload, &typelen);

	remotechan = buf_getint(ses.payload);
	transwindow = buf_getint(ses.payload);
	transwindow = MIN(transwindow, MAX_TRANS_WINDOW);
	transmaxpacket = buf_getint(ses.payload);
	transmaxpacket = MIN(transmaxpacket, MAX_TRANS_PAYLOAD_LEN);

	/* figure what type of packet it is */
	if (typelen > MAX_NAME_LEN) {
		goto failure;
	}

	/* Get the channel type. Client and server style invokation will set up a
	 * different list for ses.chantypes at startup. We just iterate through
	 * this list and find the matching name */
	for (cp = &ses.chantypes[0], chantype = (*cp); 
			chantype != NULL;
			cp++, chantype = (*cp)) {
		if (strcmp(type, chantype->name) == 0) {
			break;
		}
	}

	if (chantype == NULL) {
		TRACE(("No matching type for '%s'", type))
		goto failure;
	}

	TRACE(("matched type '%s'", type))

	/* create the channel */
	channel = newchannel(remotechan, chantype, transwindow, transmaxpacket);

	if (channel == NULL) {
		TRACE(("newchannel returned NULL"))
		goto failure;
	}

	if (channel->type->inithandler) {
		ret = channel->type->inithandler(channel);
		if (ret > 0) {
			if (ret == SSH_OPEN_IN_PROGRESS) {
				/* We'll send the confirmation later */
				goto cleanup;
			}
			errtype = ret;
			deletechannel(channel);
			TRACE(("inithandler returned failure %d", ret))
			goto failure;
		}
	}

	/* success */
	send_msg_channel_open_confirmation(channel, channel->recvwindow,
			channel->recvmaxpacket);
	goto cleanup;

failure:
	TRACE(("recv_msg_channel_open failure"))
	send_msg_channel_open_failure(remotechan, errtype, "", "");

cleanup:
	m_free(type);

	TRACE(("leave recv_msg_channel_open"))
}

/* Send a failure message */
void send_msg_channel_failure(struct Channel *channel) {

	TRACE(("enter send_msg_channel_failure"))
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_FAILURE);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();
	TRACE(("leave send_msg_channel_failure"))
}

/* Send a success message */
void send_msg_channel_success(struct Channel *channel) {

	TRACE(("enter send_msg_channel_success"))
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_SUCCESS);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();
	TRACE(("leave send_msg_channel_success"))
}

/* Send a channel open failure message, with a corresponding reason
 * code (usually resource shortage or unknown chan type) */
static void send_msg_channel_open_failure(unsigned int remotechan, 
		int reason, const unsigned char *text, const unsigned char *lang) {

	TRACE(("enter send_msg_channel_open_failure"))
	CHECKCLEARTOWRITE();
	
	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_FAILURE);
	buf_putint(ses.writepayload, remotechan);
	buf_putint(ses.writepayload, reason);
	buf_putstring(ses.writepayload, text, strlen((char*)text));
	buf_putstring(ses.writepayload, lang, strlen((char*)lang));

	encrypt_packet();
	TRACE(("leave send_msg_channel_open_failure"))
}

/* Confirm a channel open, and let the remote end know what number we've
 * allocated and the receive parameters */
static void send_msg_channel_open_confirmation(struct Channel* channel,
		unsigned int recvwindow, 
		unsigned int recvmaxpacket) {

	TRACE(("enter send_msg_channel_open_confirmation"))
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putint(ses.writepayload, channel->index);
	buf_putint(ses.writepayload, recvwindow);
	buf_putint(ses.writepayload, recvmaxpacket);

	encrypt_packet();
	TRACE(("leave send_msg_channel_open_confirmation"))
}

#if defined(USING_LISTENERS) || defined(DROPBEAR_CLIENT)
/* Create a new channel, and start the open request. This is intended
 * for X11, agent, tcp forwarding, and should be filled with channel-specific
 * options, with the calling function calling encrypt_packet() after
 * completion. It is mandatory for the caller to encrypt_packet() if
 * DROPBEAR_SUCCESS is returned */
int send_msg_channel_open_init(int fd, const struct ChanType *type) {

	struct Channel* chan;

	TRACE(("enter send_msg_channel_open_init()"))
	chan = newchannel(0, type, 0, 0);
	if (!chan) {
		TRACE(("leave send_msg_channel_open_init() - FAILED in newchannel()"))
		return DROPBEAR_FAILURE;
	}

	/* set fd non-blocking */
	setnonblocking(fd);

	chan->infd = chan->outfd = fd;
	ses.maxfd = MAX(ses.maxfd, fd);

	/* now open the channel connection */
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN);
	buf_putstring(ses.writepayload, type->name, strlen(type->name));
	buf_putint(ses.writepayload, chan->index);
	buf_putint(ses.writepayload, RECV_MAXWINDOW);
	buf_putint(ses.writepayload, RECV_MAXPACKET);

	TRACE(("leave send_msg_channel_open_init()"))
	return DROPBEAR_SUCCESS;
}

/* Confirmation that our channel open request (for forwardings) was 
 * successful*/
void recv_msg_channel_open_confirmation() {

	struct Channel * channel;
	int ret;

	TRACE(("enter recv_msg_channel_open_confirmation"))

	channel = getchannel();
	if (channel == NULL) {
		dropbear_exit("Unknown channel");
	}

	channel->remotechan =  buf_getint(ses.payload);
	channel->transwindow = buf_getint(ses.payload);
	channel->transmaxpacket = buf_getint(ses.payload);
	
	TRACE(("new chan remote %d local %d", 
				channel->remotechan, channel->index))

	/* Run the inithandler callback */
	if (channel->type->inithandler) {
		ret = channel->type->inithandler(channel);
		if (ret > 0) {
			removechannel(channel);
			TRACE(("inithandler returned failure %d", ret))
		}
	}

	
	TRACE(("leave recv_msg_channel_open_confirmation"))
}

/* Notification that our channel open request failed */
void recv_msg_channel_open_failure() {

	struct Channel * channel;

	channel = getchannel();
	if (channel == NULL) {
		dropbear_exit("Unknown channel");
	}

	removechannel(channel);
}
#endif /* USING_LISTENERS */

/* close a stdout/stderr fd */
static void closeoutfd(struct Channel * channel, int fd) {

	/* don't close it if it is the same as infd,
	 * unless infd is already set -1 */
	TRACE(("enter closeoutfd"))
	closechanfd(channel, fd, 0);
	TRACE(("leave closeoutfd"))
}

/* close a stdin fd */
static void closeinfd(struct Channel * channel) {

	TRACE(("enter closeinfd"))
	closechanfd(channel, channel->infd, 1);
	TRACE(("leave closeinfd"))
}

/* close a fd, how is 0 for stdout/stderr, 1 for stdin */
static void closechanfd(struct Channel *channel, int fd, int how) {

	int closein = 0, closeout = 0;

	/* XXX server */
	if (channel->type->sepfds) {
		TRACE(("shutdown((%d), %d)", fd, how))
		shutdown(fd, how);
		if (how == 0) {
			closeout = 1;
		} else {
			closein = 1;
		}
	} else {
		close(fd);
		closein = closeout = 1;
	}

	if (closeout && fd == channel->outfd) {
		channel->outfd = FD_CLOSED;
	}
	if (closeout && (channel->extrabuf == NULL) && (fd == channel->errfd)) {
		channel->errfd = FD_CLOSED;
	}

	if (closein && fd == channel->infd) {
		channel->infd = FD_CLOSED;
	}
	if (closein && (channel->extrabuf != NULL) && (fd == channel->errfd)) {
		channel->errfd = FD_CLOSED;
	}

	/* if we called shutdown on it and all references are gone, then we 
	 * need to close() it to stop it lingering */
	if (channel->type->sepfds && channel->outfd == FD_CLOSED 
		&& channel->infd == FD_CLOSED && channel->errfd == FD_CLOSED) {
		close(fd);
	}
}
