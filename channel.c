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

/* Handle the multiplexed channels, such as sessions, x11, agent connections */

#include "includes.h"
#include "session.h"
#include "packet.h"
#include "ssh.h"
#include "buffer.h"
#include "util.h"
#include "channel.h"
#include "chansession.h"
#include "ssh.h"
#include "x11fwd.h"
#include "agentfwd.h"
#include "localtcpfwd.h"

static void send_msg_channel_open_failure(unsigned int remotechan, int reason,
		const unsigned char *text, const unsigned char *lang);
static void send_msg_channel_open_confirmation(struct Channel* channel,
		unsigned int recvwindow, 
		unsigned int recvmaxpacket);
static void writechannel(struct Channel *channel);
static void send_msg_channel_window_adjust(struct Channel *channel, 
		unsigned int incr);
static void send_msg_channel_data(struct Channel *channel, int isextended,
		unsigned int exttype);
static void send_msg_channel_eof(struct Channel *channel);
static void send_msg_channel_close(struct Channel *channel);
static void closechannel(struct Channel *channel);
static void deletechannel(struct Channel *channel);
static void send_exitsignalstatus(struct Channel *channel);
static void checkinitdone(struct Channel *channel);

/* initialise channels */
void chaninitialise() {

	/* may as well create space for a single channel */
	ses.channels = (struct Channel**)m_malloc(sizeof(struct Channel*));
	ses.chansize = 1;
	ses.channels[0] = NULL;

	chansessinitialise();
}

/* Clean up channels, freeing allocated memory */
void chancleanup() {

	unsigned int i;

	TRACE(("enter chancleanup"));
	for (i = 0; i < ses.chansize; i++) {
		if (ses.channels[i] != NULL) {
			TRACE(("channel %d closing", i));
			closechannel(ses.channels[i]);
		}
	}
	m_free(ses.channels);
	TRACE(("leave chancleanup"));
}

/* create a new channel entry, send a reply confirm or failure */
/* If remotechan, transwindow and transmaxpacket are not know (for a new
 * outgoing connection, with them to be filled on confirmation), they should
 * all be set to 0 */
struct Channel* newchannel(unsigned int remotechan, unsigned char type, 
		unsigned int transwindow, unsigned int transmaxpacket) {

	struct Channel * newchan;
	unsigned int i, j;

	TRACE(("enter newchannel"));
	
	/* first see if we can use existing channels */
	for (i = 0; i < ses.chansize; i++) {
		if (ses.channels[i] == NULL) {
			break;
		}
	}

	/* otherwise extend the list */
	if (i == ses.chansize) {
		if (ses.chansize > MAX_CHANNELS) {
			TRACE(("leave newchannel: max chans reached"));
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
	newchan->sentclosed = 0;
	newchan->recveof = newchan->transeof = newchan->erreof = 0;

	newchan->remotechan = remotechan;
	newchan->transwindow = transwindow;
	newchan->transmaxpacket = transmaxpacket;
	
	newchan->typedata = NULL;
	newchan->infd = -1;
	newchan->outfd = -1;
	newchan->errfd = -1;
	newchan->initconn = 0;

	newchan->writebuf = buf_new(RECV_MAXWINDOW);
	newchan->recvwindow = RECV_MAXWINDOW;
	newchan->recvmaxpacket = RECV_MAXPACKET;

	ses.channels[i] = newchan;

	TRACE(("leave newchannel"));

	return newchan;
}

/* Get the channel structure corresponding to a channel number */
static struct Channel* getchannel(unsigned int chan) {
	if (chan >= ses.chansize || ses.channels[chan] == NULL) {
		return NULL;
	}
	return ses.channels[chan];
}

/* Iterate through the channels, performing IO if available */
void channelio(fd_set *readfd, fd_set *writefd) {

	struct Channel *channel;
	unsigned int i;

	for (i = 0; i < ses.chansize; i++) {

		channel = ses.channels[i];
		if (channel == NULL || channel->sentclosed) {
			continue;
		}

		/* read from program/pipe/etc stdout */
		if (channel->outfd != -1 && channel->transeof == 0 &&
				FD_ISSET(channel->outfd, readfd)) {
			send_msg_channel_data(channel, 0, 0);
		}
		/* read from program/pipe stderr for interactive sessions */
		if (channel->errfd != -1 && channel->erreof == 0 &&
				FD_ISSET(channel->errfd, readfd)) {
				send_msg_channel_data(channel, 1, SSH_EXTENDED_DATA_STDERR);
		}
		/* write to program/pipe stdin */
		if (channel->infd != -1 && channel->recveof == 0 &&
				FD_ISSET(channel->infd, writefd)) {
			if (channel->initconn) {
				checkinitdone(channel);
				continue; /* Important not to use the channel after
							 checkinitdone(), as it may be NULL */
			} else {
				writechannel(channel);
			}
		}
		
		/* handle any listening sockets */
		if (channel->type == CHANNEL_ID_SESSION) {
			struct ChanSess * chansess = (struct ChanSess*)channel->typedata;
#ifndef DISABLE_X11FWD
			if (chansess->x11fd != -1 && FD_ISSET(chansess->x11fd, readfd)) {
				x11accept(chansess);
			}
#endif
#ifndef DISABLE_AGENTFWD
			if (chansess->agentfd != -1 && FD_ISSET(chansess->agentfd,readfd)) {
				agentaccept(chansess);
			}
#endif
		}
	} /* foreach channel */

}

/* Check whether a deferred (EINPROGRESS) connect() was successful, and
 * if so, set up the channel properly. Otherwise, the channel is cleaned up, so
 * it is important that the channel reference isn't used after a call to this
 * function */
static void checkinitdone(struct Channel *channel) {

	int val;
	socklen_t vallen = sizeof(val);

	TRACE(("enter checkinitdone"));

	if (getsockopt(channel->infd, SOL_SOCKET, SO_ERROR, &val, &vallen)
			|| val != 0) {
		close(channel->infd);
		deletechannel(channel);
		TRACE(("leave checkinitdone: fail"));
	} else {
		channel->outfd = channel->infd;
		channel->initconn = 0;
		TRACE(("leave checkinitdone: success"));
	}
}


/* send the exit status or the signal causing termination for a session */
static void send_exitsignalstatus(struct Channel *channel) {

	struct ChanSess * chansess;
	chansess = (struct ChanSess*)channel->typedata;

	if (chansess->exited) {
		if (chansess->exitsignal > 0) {
			send_msg_chansess_exitsignal(channel, chansess);
		} else {
			send_msg_chansess_exitstatus(channel, chansess);
		}
	}
}


/* Send the close message and set the channel as closed */
static void send_msg_channel_close(struct Channel *channel) {

	TRACE(("enter send_msg_channel_close"));
	if (channel->type == CHANNEL_ID_SESSION) {
		send_exitsignalstatus(channel);
	}
	
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_CLOSE);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();

	channel->sentclosed = 1;
	TRACE(("leave send_msg_channel_close"));
}

/* call this when trans/eof channels are closed */
static void send_msg_channel_eof(struct Channel *channel) {

	TRACE(("enter send_msg_channel_eof"));
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_EOF);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();

	/* we already know that trans/eof channels are closed */
	send_msg_channel_close(channel);

	TRACE(("leave send_msg_channel_eof"));
}

/* Called to write data out to the server side of a channel (eg a shell or a
 * program.
 * Only called when we know we can write to a channel, writes as much as
 * possible */
static void writechannel(struct Channel* channel) {

	int len, maxlen;
	buffer *buf;

	TRACE(("enter writechannel"));

	if (channel->recveof || channel->sentclosed) {
		TRACE(("leave writechannel: already recveof or sentclosed"));
		return;
	}

	buf = channel->writebuf;
	maxlen = buf->len - buf->pos;

	len = write(channel->infd, buf_getptr(buf, maxlen), maxlen);
	if (len <= 0) {
		if (errno != EINTR) {

			/* no more to write */
			channel->recveof = 1;

			/* if everything's closed then close it all up */
			if (channel->transeof && 
					(channel->erreof || channel->errfd == -1)) {
				send_msg_channel_close(channel);
			}
		}
		TRACE(("leave writechannel: len <= 0"));
		return;
	}
	
	/* extend the window */
	/* TODO - this is inefficient */
	if (len == maxlen) {
		buf_setpos(buf, 0);
		buf_setlen(buf, 0);
		send_msg_channel_window_adjust(channel, buf->size
				- channel->recvwindow);
		channel->recvwindow = buf->size;
	} else {
		buf_incrpos(buf, len);
	}
	TRACE(("leave writechannel"));
}

/* Set the file descriptors for the main select in session.c
 * This avoid channels which don't have any window available, are closed, etc*/
void setchannelfds(fd_set *readfd, fd_set *writefd) {
	
	unsigned int i;
	struct Channel * channel;
	
	for (i = 0; i < ses.chansize; i++) {

		channel = ses.channels[i];
		if (channel == NULL || channel->sentclosed == 1) {
			continue;
		}

		/* stdout and stderr */
		if (channel->transwindow > 0) {

			/* stdout */
			if (channel->outfd != -1 && channel->transeof == 0) {
				/* there's space to read more from the program */
				FD_SET(channel->outfd, readfd);
			}
			/* stderr for interactive sessions */
			if (channel->errfd != -1 && channel->erreof == 0) {
					FD_SET(channel->errfd, readfd);
			}
		}
		/* stdin */
		if (channel->infd != -1 && channel->recveof == 0 &&
				(channel->writebuf->pos < channel->writebuf->len ||
				 channel->initconn)) {
			/* there's space to write more to the program */
			FD_SET(channel->infd, writefd);
		}

		/* handle any listening sockets - should get optimised away if
		 * we don't have x11 or agent fwd */
		if (channel->type == CHANNEL_ID_SESSION) {
			struct ChanSess * chansess = (struct ChanSess*)channel->typedata;
#ifndef DISABLE_X11FWD
			if (chansess->x11fd != -1) {
				FD_SET(chansess->x11fd, readfd);
			}
#endif
#ifndef DISABLE_AGENTFWD
			if (chansess->agentfd != -1) {
				FD_SET(chansess->agentfd, readfd);
			}
#endif
		}
	} /* foreach channel */

}

/* handle the channel EOF event, by closing the channel filedescriptor. The
 * channel isn't closed yet, it is left until the incoming (from the program
 * etc) FD is also EOF */
void recv_msg_channel_eof() {

	unsigned int chan;
	struct Channel * channel;

	TRACE(("enter recv_msg_channel_eof"));

	chan = buf_getint(ses.payload);
	channel = getchannel(chan);

	if (channel == NULL) {
		dropbear_exit("EOF for unknown channel");
	}

	channel->recveof = 1;

	/* we should close the channel */
	if (channel->type == CHANNEL_ID_X11 || channel->type == CHANNEL_ID_AGENT
			|| channel->type == CHANNEL_ID_TCPDIRECT) {
		shutdown(channel->infd, 0);
	} else {
		close(channel->infd);
	}
	channel->infd = -1;

	if (channel->transeof && (channel->erreof || channel->errfd == -1)
			&& !channel->sentclosed) {
		send_msg_channel_close(channel);
	}

	TRACE(("leave recv_msg_channel_eof"));
}


/* Handle channel closure(), respond in kind and close the channels */
void recv_msg_channel_close() {

	unsigned int chan;
	struct Channel * channel;

	TRACE(("enter recv_msg_channel_close"));

	chan = buf_getint(ses.payload);
	TRACE(("close channel = %d", chan));
	channel = getchannel(chan);

	if (channel == NULL) {
		/* disconnect ? */
		dropbear_exit("Close for unknown channel");
	}

	if (!channel->sentclosed) {
		send_msg_channel_close(channel);
	}

	closechannel(channel);
	
	TRACE(("leave recv_msg_channel_close"));
}

/* Remove a channel entry, this is only executed after both sides have sent
 * channel close */
static void closechannel(struct Channel * channel) {

	TRACE(("enter closechannel"));
	TRACE(("channel index is %d", channel->index));
	
	buf_free(channel->writebuf);

	/* close the FDs in case they haven't been done
	 * yet (ie they were shutdown etc */
	close(channel->infd);
	close(channel->outfd);

	if (channel->type == CHANNEL_ID_SESSION) {
		closechansess(channel);
	}

	deletechannel(channel);

	TRACE(("leave closechannel"));
}

/* Just remove a channel entry, don't try to close descriptors etc */
static void deletechannel(struct Channel *channel) {

	ses.channels[channel->index] = NULL;
	m_free(channel);
	
}


/* Handle channel specific requests, passing off to corresponding handlers
 * such as chansession or x11fwd */
void recv_msg_channel_request() {

	unsigned int chan;
	struct Channel *channel;

	TRACE(("enter recv_msg_channel_request"));
	
	chan = buf_getint(ses.payload);
	channel = getchannel(chan);

	if (channel == NULL) {
		/* disconnect ? */
		dropbear_exit("Unknown channel");
	}


	TRACE(("chan type is %d", channel->type));

	/* handle according to channel type */
	switch (channel->type) {

		case CHANNEL_ID_SESSION:
			TRACE(("continue recv_msg_channel_request: session request"));
			chansessionrequest(channel);
			break;

		default:
			send_msg_channel_failure(channel);
	}

	TRACE(("leave recv_msg_channel_request"));

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

	TRACE(("enter send_msg_channel_data"));
	TRACE(("extended = %d type = %d", isextended, exttype));

	CHECKCLEARTOWRITE();

	assert(!channel->sentclosed);

	if (isextended) {
		if (channel->erreof) {
			TRACE(("leave send_msg_channel_data: erreof already set"));
			return;
		}
		assert(exttype == SSH_EXTENDED_DATA_STDERR);
		fd = channel->errfd;
	} else {
		if (channel->transeof) {
			TRACE(("leave send_msg_channel_data: transeof already set"));
			return;
		}
		fd = channel->outfd;
	}
	assert(fd >= 0);

	maxlen = MIN(channel->transwindow, channel->transmaxpacket);
	/* -(1+4+4) is SSH_MSG_CHANNEL_DATA, channel number, string length, and 
	 * exttype if is extended */
	maxlen = MIN(maxlen, ses.writepayload->size 
			- 1 - 4 - 4 - (isextended ? 4 : 0));
	if (maxlen == 0) {
		TRACE(("leave send_msg_channel_data: no window"));
		return; /* the data will get written later */
	}

	/* read the data */
	buf = buf_new(maxlen);
	len = read(fd, buf_getwriteptr(buf, maxlen), maxlen);
	if (len <= 0) {
		/* on error etc, send eof */
		if (errno != EINTR) {
			
			if (isextended) {
				channel->erreof = 1;
			} else {
				channel->transeof = 1;
			}
			
			if ((channel->erreof || channel->errfd == -1)
					&& channel->transeof) {
				send_msg_channel_eof(channel);
			}
		}
		buf_free(buf);
		TRACE(("leave send_msg_channel_data: len <= 0, erreof %d transeof %d",
					channel->erreof, channel->transeof));
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

	channel->transwindow -= len;

	encrypt_packet();
	TRACE(("leave send_msg_channel_data"));
}


/* when we receive channel data, put it in a buffer for writing to the program/
 * shell etc */
void recv_msg_channel_data() {

	unsigned int chan;
	struct Channel * channel;
	unsigned int datalen;
	unsigned int pos;
	unsigned int maxdata;

	TRACE(("enter recv_msg_channel_data"));
	
	chan = buf_getint(ses.payload);
	channel = getchannel(chan);
	if (channel == NULL) {
		/* disconnect ? */
		dropbear_exit("Unknown channel");
	}

	assert(channel->infd != -1);

	datalen = buf_getint(ses.payload);

	/* if the client is going to send us more data than we've allocated, then 
	 * it has ignored the windowsize, so we "MAY ignore all extra data" */
	maxdata = channel->writebuf->size - channel->writebuf->pos;
	if (datalen > maxdata) {
		TRACE(("Warning: recv_msg_channel_data: extra data past window"));
		datalen = maxdata;
	}

	/* write to the buffer - we always append to the end of the buffer */
	pos = channel->writebuf->pos;
	buf_setpos(channel->writebuf, channel->writebuf->len);
	memcpy(buf_getwriteptr(channel->writebuf, datalen), 
			buf_getptr(ses.payload, datalen), datalen);
	buf_incrwritepos(channel->writebuf, datalen);
	buf_setpos(channel->writebuf, pos); /* revert pos */

	channel->recvwindow -= datalen;
/*	if (channel->recvwindow < RECV_MINWINDOW) {
		send_msg_channel_window_adjust(channel, 
				RECV_MAXWINDOW - channel->recvwindow);
		channel->recvwindow = RECV_MAXWINDOW;
	}*/

	TRACE(("leave recv_msg_channel_data"));
}

/* Increment the outgoing data window for a channel - the remote end limits
 * the amount of data which may be transmitted, this window is decremented
 * as data is sent, and incremented upon receiving window-adjust messages */
void recv_msg_channel_window_adjust() {

	unsigned int chan;
	struct Channel * channel;
	unsigned int incr;
	
	chan = buf_getint(ses.payload);
	channel = getchannel(chan);

	if (channel == NULL) {
		dropbear_exit("Unknown channel"); /* TODO - disconnect */
	}
	
	incr = buf_getint(ses.payload);
	TRACE(("received window increment %d", incr));
	incr = MIN(incr, MAX_TRANS_WIN_INCR);
	
	channel->transwindow += incr;
	channel->transwindow = MIN(channel->transwindow, MAX_TRANS_WINDOW);

}

/* Increment the incoming data window for a channel, and let the remote
 * end know */
static void send_msg_channel_window_adjust(struct Channel* channel, 
		unsigned int incr) {

	TRACE(("sending window adjust %d", incr));
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_WINDOW_ADJUST);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putint(ses.writepayload, incr);

	encrypt_packet();
}
	
/* Handle a new channel request, performing any channel-type-specific setup */
void recv_msg_channel_open() {

	unsigned char* type;
	unsigned int typelen;
	unsigned int typeval;
	unsigned int remotechan, transwindow, transmaxpacket;
	struct Channel* channel;
	unsigned int errtype = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;


	TRACE(("enter recv_msg_channel_open"));

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
	if (strcmp(type, "session") == 0) {
		typeval = CHANNEL_ID_SESSION;
#ifndef DISABLE_LOCALTCPFWD
	} else if (strcmp(type, "direct-tcpip") == 0) {
		typeval = CHANNEL_ID_TCPDIRECT;
#endif
	} else {
		goto failure;
	}

	/* create the channel */
	channel = newchannel(remotechan, typeval, transwindow, transmaxpacket);

	if (channel == NULL) {
		errtype = SSH_OPEN_RESOURCE_SHORTAGE;
		goto failure;
	}
	
	/* type specific initialisation */
	if (typeval == CHANNEL_ID_SESSION) {
		newchansess(channel);
#ifndef DISABLE_LOCALTCPFWD
	} else if (typeval == CHANNEL_ID_TCPDIRECT) {
		if (newtcpdirect(channel) == DROPBEAR_FAILURE) {
			deletechannel(channel);
			goto failure;
		}
#endif
	}

	/* success */
	send_msg_channel_open_confirmation(channel, channel->recvwindow,
			channel->recvmaxpacket);
	goto cleanup;

failure:
	send_msg_channel_open_failure(remotechan, errtype, "", "");

cleanup:
	m_free(type);

	TRACE(("leave recv_msg_channel_open"));
}

/* Send a failure message */
void send_msg_channel_failure(struct Channel *channel) {

	TRACE(("enter send_msg_channel_failure"));
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_FAILURE);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();
	TRACE(("leave send_msg_channel_failure"));
}

/* Send a success message */
void send_msg_channel_success(struct Channel *channel) {

	TRACE(("enter send_msg_channel_success"));
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_SUCCESS);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();
	TRACE(("leave send_msg_channel_success"));
}

/* Send a channel open failure message, with a corresponding reason
 * code (usually resource shortage or unknown chan type) */
static void send_msg_channel_open_failure(unsigned int remotechan, 
		int reason, const unsigned char *text, const unsigned char *lang) {

	TRACE(("enter send_msg_channel_open_failure"));
	CHECKCLEARTOWRITE();
	
	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_FAILURE);
	buf_putint(ses.writepayload, remotechan);
	buf_putint(ses.writepayload, reason);
	buf_putstring(ses.writepayload, text, strlen((char*)text));
	buf_putstring(ses.writepayload, lang, strlen((char*)lang));

	encrypt_packet();
	TRACE(("leave send_msg_channel_open_failure"));
}

/* Confirm a channel open, and let the remote end know what number we've
 * allocated and the receive parameters */
static void send_msg_channel_open_confirmation(struct Channel* channel,
		unsigned int recvwindow, 
		unsigned int recvmaxpacket) {

	TRACE(("enter send_msg_channel_open_confirmation"));
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putint(ses.writepayload, channel->index);
	buf_putint(ses.writepayload, recvwindow);
	buf_putint(ses.writepayload, recvmaxpacket);

	encrypt_packet();
	TRACE(("leave send_msg_channel_open_confirmation"));
}

#ifdef USE_LISTENERS
/* Create a new channel, and start the open request. This is intended
 * for X11, agent, tcp forwarding, and should be filled with channel-specific
 * options, with the calling function calling encrypt_packet() after
 * completion. It is mandatory for the caller to encrypt_packet() if
 * DROPBEAR_SUCCESS is returned */
int send_msg_channel_open_init(int fd, const char * typestring) {

	struct Channel* chan;

	chan = newchannel(0, CHANNEL_ID_AGENT, 0, 0);
	if (!chan) {
		return DROPBEAR_FAILURE;
	}

	/* set fd non-blocking */
	if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		return DROPBEAR_FAILURE;
	}

	chan->infd = chan->outfd = fd;
	ses.maxfd = MAX(ses.maxfd, fd);

	/* now open the channel connection */
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN);
	buf_putstring(ses.writepayload, typestring, strlen(typestring));
	buf_putint(ses.writepayload, chan->index);
	buf_putint(ses.writepayload, RECV_MAXWINDOW);
	buf_putint(ses.writepayload, RECV_MAXPACKET);

	return DROPBEAR_SUCCESS;
}

/* Confirmation that our channel open request (for forwardings) was 
 * successful*/
void recv_msg_channel_open_confirmation() {

	unsigned int chan;
	struct Channel * channel;

	TRACE(("enter recv_msg_channel_open_confirmation"));
	chan = buf_getint(ses.payload);

	channel = getchannel(chan);
	if (channel == NULL) {
		dropbear_exit("Unknown channel");
	}

	channel->remotechan =  buf_getint(ses.payload);
	channel->transwindow = buf_getint(ses.payload);
	channel->transmaxpacket = buf_getint(ses.payload);

	TRACE(("leave recv_msg_channel_open_confirmation"));
}

/* Notification that our channel open request failed */
void recv_msg_channel_open_failure() {

	unsigned int chan;
	struct Channel * channel;
	chan = buf_getbyte(ses.payload);

	channel = getchannel(chan);
	if (channel == NULL) {
		dropbear_exit("Unknown channel");
	}

	closechannel(channel);
}
#endif /* USE_LISTENERS */
