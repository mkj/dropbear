#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>

#include "options.h"
#include "session.h"
#include "packet.h"
#include "ssh.h"
#include "buffer.h"
#include "util.h"
#include "channel.h"
#include "chansession.h"
#include "ssh.h"

static struct Channel* newchannel(unsigned int remotechan, char type, 
		unsigned int transwindow, unsigned int transmaxpacket);
static void send_msg_channel_open_failure(unsigned int remotechan, int reason,
		const unsigned char *text, const unsigned char *lang);
static void send_msg_channel_open_success(struct Channel* channel,
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
static void send_exitsignalstatus(struct Channel *channel);

/* initialise channels */
void chaninitialise() {

	/* may as well create space for a single channel */
	ses.channels = (struct Channel**)m_malloc(sizeof(struct Channel*));
	ses.chansize = 1;
	ses.channels[0] = NULL;

	chansessinitialise();
}

void chancleanup() {

	int i;

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
static struct Channel* newchannel(unsigned int remotechan, char type, 
		unsigned int transwindow, unsigned int transmaxpacket) {

	struct Channel ** chanlist;
	struct Channel * newchan;
	int i;

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
			send_msg_channel_open_failure(remotechan,
					SSH_OPEN_RESOURCE_SHORTAGE, "", "");
			TRACE(("enter newchannel: max chans reached"));
			return NULL;
		}

		/* extend the channels */
		chanlist = (struct Channel**)m_realloc(ses.channels,
				(ses.chansize+CHAN_EXTEND_SIZE)*sizeof(struct Channel*));

		ses.channels = chanlist;
		ses.chansize += CHAN_EXTEND_SIZE;
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

	newchan->writebuf = buf_new(RECV_MAXWINDOW);
	newchan->recvwindow = RECV_MAXWINDOW;
	newchan->recvmaxpacket = RECV_MAXPACKET;

	ses.channels[i] = newchan;

	send_msg_channel_open_success(newchan, RECV_MAXWINDOW,
			RECV_MAXPACKET);
	TRACE(("enter newchannel"));

	return newchan;
}

static struct Channel* getchannel(unsigned int chan) {
	if (chan >= ses.chansize || ses.channels[chan] == NULL) {
		return NULL;
	}
	return ses.channels[chan];
}

void channelio(fd_set *readfd, fd_set *writefd) {

	struct Channel *channel;
	int i;

	for (i = 0; i < ses.chansize; i++) {

		channel = ses.channels[i];
		if (channel == NULL || channel->sentclosed) {
			continue;
		}

		/* read from program stdout */
		if (channel->outfd != -1 && channel->transeof == 0 &&
				FD_ISSET(channel->outfd, readfd)) {
			send_msg_channel_data(channel, 0, 0);
		}
		/* read from program stderr for interactive sessions */
		if (channel->errfd != -1 && channel->erreof == 0 &&
				FD_ISSET(channel->errfd, readfd)) {
				send_msg_channel_data(channel, 1, SSH_EXTENDED_DATA_STDERR);
		}
		/* write to program stdin */
		if (channel->infd != -1 && channel->recveof == 0 &&
				FD_ISSET(channel->infd, writefd)) {
			writechannel(channel);
		}
	}
}

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
/* only called when we know we can write to a channel, writes as much as
 * possible */
static void writechannel(struct Channel* channel) {

	int len, maxlen;
	buffer *buf;

	TRACE(("enter writechannel"));

	assert(!channel->sentclosed);

	if (channel->recveof) {
		TRACE(("leave writechannel: already recveof"));
		return;
	}

	buf = channel->writebuf;
	maxlen = buf->len - buf->pos;

	len = write(channel->infd, buf_getptr(buf, maxlen), maxlen);
	if (len <= 0) {
		if (errno != EINTR) {

			/* no more to write */
			channel->recveof = 1;

			/* if everything's closed the close it all up */
			if (channel->transeof && 
					(channel->erreof || channel->errfd == -1)) {
				send_msg_channel_close(channel);
			}
		}
		TRACE(("leave writechannel: len <= 0"));
		return;
	}
	
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

void setchannelfds(fd_set *readfd, fd_set *writefd) {
	
	int i;
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
				channel->writebuf->pos < channel->writebuf->len) {
			/* there's space to write more to the program */
			FD_SET(channel->infd, writefd);
		}
	}
}

void recv_msg_channel_eof() {

	unsigned int chan;
	struct Channel * channel;

	TRACE(("enter recv_msg_channel_eof"));

	chan = buf_getint(ses.payload);
	channel = getchannel(chan);

	if (channel == NULL) {
		dropbear_exit("EOF for unknown channel");
	}
	assert(ses.authstate.authdone);

	channel->recveof = 1;

	if (channel->transeof && (channel->erreof || channel->errfd == -1)
			&& !channel->sentclosed) {
		send_msg_channel_close(channel);
	}

	TRACE(("leave recv_msg_channel_eof"));
}


void recv_msg_channel_close() {

	unsigned int chan;
	struct Channel * channel;

	TRACE(("enter recv_msg_channel_close"));

	chan = buf_getint(ses.payload);
	channel = getchannel(chan);

	if (channel == NULL) {
		/* disconnect ? */
		dropbear_exit("Close for unknown channel");
	}
	assert(ses.authstate.authdone);

	if (!channel->sentclosed) {
		send_msg_channel_close(channel);
	}

	closechannel(channel);
	
	TRACE(("leave recv_msg_channel_close"));
}

static void closechannel(struct Channel * channel) {

	unsigned int index;

	TRACE(("enter closechannel"));
	TRACE(("channel index is %d", channel->index));
	
	buf_free(channel->writebuf);
	TRACE(("frees done "));

	if (channel->type == CHANNEL_ID_SESSION) {
		closechansess(channel);
	}

	index = channel->index;
	m_free(channel);
	ses.channels[index] = NULL;
	TRACE(("leave closechannel"));
}

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

	/* if the channel exists, then we've checked for auth when creating */
	assert(ses.authstate.authdone);

	TRACE(("chan type is %d", channel->type));

	/* handle according to channel type */
	switch (channel->type) {

		case CHANNEL_ID_SESSION:
			TRACE(("continue recv_msg_channel_request: session request"));
			chansessionrequest(channel);
			break;

		case CHANNEL_ID_X11:

		default:
			send_msg_channel_failure(channel);
	}

	TRACE(("leave recv_msg_channel_request"));

}

/* chan is the remote channel, isextended is 0 if it is normal data, 1
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
		} else {
			fprintf(stderr, "EINTR happened!\n");
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


/* when we receive channel data */
void recv_msg_channel_data() {

	unsigned int chan;
	struct Channel * channel;
	unsigned int datalen;
	unsigned int pos;

	TRACE(("enter recv_msg_channel_data"));
	
	chan = buf_getint(ses.payload);
	channel = getchannel(chan);
	if (channel == NULL) {
		/* disconnect ? */
		dropbear_exit("Unknown channel");
	}

	assert(ses.authstate.authdone);
	assert(channel->infd != -1);
	assert(channel->sentclosed == 0);

	datalen = buf_getint(ses.payload);

	/* if the client is going to send us more data than we've allocated, then 
	 * it has ignored the windowsize, so we "MAY ignore all extra data" */
	if (datalen > channel->writebuf->size - channel->writebuf->pos) {
		TRACE(("Warning: recv_msg_channel_data: extra data past window"));
		datalen = channel->writebuf->size - channel->writebuf->pos;
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

void recv_msg_channel_window_adjust() {

	unsigned int chan;
	struct Channel * channel;
	unsigned int incr;
	
	chan = buf_getint(ses.payload);
	channel = getchannel(chan);

	if (channel == NULL) {
		dropbear_exit("Invalid channel"); /* TODO - disconnect */
	}
	
	incr = buf_getint(ses.payload);
	TRACE(("received window increment %d", incr));
	incr = MIN(incr, MAX_TRANS_WIN_INCR);
	
	channel->transwindow += incr;

}

static void send_msg_channel_window_adjust(struct Channel* channel, 
		unsigned int incr) {

	TRACE(("sending window adjust %d", incr));
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_WINDOW_ADJUST);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putint(ses.writepayload, incr);

	encrypt_packet();
}
	
void recv_msg_channel_open() {

	unsigned char* type;
	unsigned int typelen;
	unsigned int remotechan, transwindow, transmaxpacket;
	struct Channel* channel;


	TRACE(("enter recv_msg_channel_open"));

	/* check we have auth */
	if (ses.authstate.authdone != 1) {
		dropbear_exit("Attempt to open channel before userauth");
	}
	
	type = buf_getstring(ses.payload, &typelen);

	TRACE(("thing here"));
	remotechan = buf_getint(ses.payload);
	TRACE(("thing here"));
	transwindow = buf_getint(ses.payload);
	transwindow = MIN(transwindow, MAX_TRANS_WINDOW);
	TRACE(("thing here"));
	transmaxpacket = buf_getint(ses.payload);
	TRACE(("thing here"));
	transmaxpacket = MIN(transmaxpacket, MAX_TRANS_PAYLOAD_LEN);


	if (typelen > MAX_NAME_LEN) {
		/* send channel_open_failure below */
	} else if (strcmp(type, "session") == 0) {
			channel = newchannel(remotechan, CHANNEL_ID_SESSION, 
					transwindow, transmaxpacket);
			if (channel != NULL) {
				newchansess(channel);
			}
			goto out;
	} else if (strcmp(type, "x11") == 0) {
			newchannel(remotechan, CHANNEL_ID_X11,
					transwindow, transmaxpacket);
			goto out;
	}

	send_msg_channel_open_failure(remotechan, 
			SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
			"Unknown channel", "en");
out:
	m_free(type);

	TRACE(("leave recv_msg_channel_open"));
}

void send_msg_channel_failure(struct Channel *channel) {

	TRACE(("enter send_msg_channel_failure"));
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_FAILURE);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();
	TRACE(("leave send_msg_channel_failure"));
}

void send_msg_channel_success(struct Channel *channel) {

	TRACE(("enter send_msg_channel_success"));
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_SUCCESS);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();
	TRACE(("leave send_msg_channel_success"));
}

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

static void send_msg_channel_open_success(struct Channel* channel,
		unsigned int recvwindow, 
		unsigned int recvmaxpacket) {

	TRACE(("enter send_msg_channel_open_success"));
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putint(ses.writepayload, channel->index);
	buf_putint(ses.writepayload, recvwindow);
	buf_putint(ses.writepayload, recvmaxpacket);

	encrypt_packet();
	TRACE(("leave send_msg_channel_open_success"));
}
