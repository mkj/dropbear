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

#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include "includes.h"
#include "buffer.h"

/* channel->type values */
#define CHANNEL_ID_NONE 0
#define CHANNEL_ID_SESSION 1
#define CHANNEL_ID_X11 2
#define CHANNEL_ID_AGENT 3
#define CHANNEL_ID_TCPDIRECT 4

#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED    1
#define SSH_OPEN_CONNECT_FAILED                 2
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE           3
#define SSH_OPEN_RESOURCE_SHORTAGE              4

#define MAX_CHANNELS 400 /* arbitrary, includes each tcp/x11 connection */
#define CHAN_EXTEND_SIZE 3 /* how many extra slots to add when we need more */

#define RECV_MAXWINDOW 6000 /* tweak */
#define RECV_MAXPACKET 1400 /* tweak */
#define RECV_MINWINDOW 19000 /* when we get below this, we send a windowadjust */

/* a simpler way to define that we need code for listeners */
#if !defined(DISABLE_X11FWD) || !defined(DISABLE_AUTHFWD) || \
	!defined(DISABLE_REMOTETCPFWD)
#define USE_LISTENERS
#endif

struct Channel {

	unsigned int index; /* the local channel index */
	unsigned int remotechan;
	unsigned char type; /* CHANNEL_ID_SESSION, CHANNEL_ID_X11 etc */
	unsigned int recvwindow, transwindow;
	unsigned int recvmaxpacket, transmaxpacket;
	void* typedata; /* a pointer to type specific data */
	int infd; /* stdin for the program, we write to this */
	int outfd; /* stdout for the program, we read from this */
	int errfd; /* stdout for a program. This doesn't really fit here,
				  but makes the code a lot tidyer without being too bad. This
				  is -1 for channels which don't requre it. Currently only
				  a 'session' without a pty will use it */
	buffer *writebuf; /* data for the program */

	int sentclosed, recvclosed;

	/* this is set when we receive/send a channel eof packet */
	int recveof, senteof;

	int initconn; /* used for TCP forwarding, whether the channel has been
					 fully initialised */

};
	
void chaninitialise();
void chancleanup();
void setchannelfds(fd_set *readfd, fd_set *writefd);
void channelio(fd_set *readfd, fd_set *writefd);
struct Channel* newchannel(unsigned int remotechan, unsigned char type, 
		unsigned int transwindow, unsigned int transmaxpacket);

void recv_msg_channel_open();
void recv_msg_channel_request();
void send_msg_channel_failure(struct Channel *channel);
void send_msg_channel_success(struct Channel *channel);
void recv_msg_channel_data();
void recv_msg_channel_window_adjust();
void recv_msg_channel_close();
void recv_msg_channel_eof();

#ifdef USE_LISTENERS
int send_msg_channel_open_init(int fd, const char * typestring);
void recv_msg_channel_open_confirmation();
void recv_msg_channel_open_failure();
#endif

#endif /* _CHANNEL_H_ */
