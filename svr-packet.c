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

#include "includes.h"
#include "packet.h"
#include "session.h"
#include "dbutil.h"
#include "ssh.h"
#include "algo.h"
#include "buffer.h"
#include "kex.h"
#include "random.h"
#include "service.h"
#include "auth.h"
#include "channel.h"

static void svr_process_postauth_packet(unsigned int type);

/* process a decrypted packet, call the appropriate handler */
void svr_process_packet() {

	unsigned char type;

	TRACE(("enter process_packet"));

	type = buf_getbyte(ses.payload);
	TRACE(("process_packet: packet type = %d", type));

	/* these packets we can receive at any time, regardless of expecting
	 * other packets: */
	switch(type) {

		case SSH_MSG_IGNORE:
		case SSH_MSG_DEBUG:
			TRACE(("received SSH_MSG_IGNORE or SSH_MSG_DEBUG"));
			goto out;

		case SSH_MSG_UNIMPLEMENTED:
			/* debugging XXX */
			TRACE(("SSH_MSG_UNIMPLEMENTED"));
			dropbear_exit("received SSH_MSG_UNIMPLEMENTED");
			
		case SSH_MSG_DISCONNECT:
			/* TODO cleanup? */
			dropbear_close("Disconnect received");
	}

	/* Check if we should ignore this packet. Used currently only for
	 * KEX code, with first_kex_packet_follows */
	if (ses.ignorenext) {
		TRACE(("Ignoring packet, type = %d", type));
		ses.ignorenext = 0;
		goto out;
	}

	/* check that we aren't expecting a particular packet */
	if (ses.expecting && ses.expecting != type) {
		/* TODO send disconnect? */
		dropbear_exit("unexpected packet type %d, expected %d", type,
				ses.expecting);
	}

	/* handle the packet depending on type */
	ses.expecting = 0;

	switch (type) {

		case SSH_MSG_SERVICE_REQUEST:
			recv_msg_service_request();
			break;

		case SSH_MSG_USERAUTH_REQUEST:
			recv_msg_userauth_request();
			break;
			
		case SSH_MSG_KEXINIT:
			recv_msg_kexinit();
			break;

		case SSH_MSG_KEXDH_INIT:
			recv_msg_kexdh_init();
			break;

		case SSH_MSG_NEWKEYS:
			recv_msg_newkeys();
			break;

		/* this is ugly, need to make a cleaner way to do it */
		case SSH_MSG_CHANNEL_DATA:
		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
		case SSH_MSG_CHANNEL_REQUEST:
		case SSH_MSG_CHANNEL_OPEN:
		case SSH_MSG_CHANNEL_EOF:
		case SSH_MSG_CHANNEL_CLOSE:
		case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
		case SSH_MSG_CHANNEL_OPEN_FAILURE:
		case SSH_MSG_GLOBAL_REQUEST:
			/* these should be checked for authdone below */
			svr_process_postauth_packet(type);
			break;
	
		default:
			/* TODO this possibly should be handled */
			TRACE(("preauth unknown packet"));
			recv_unimplemented();
			break;
	}

out:
	buf_free(ses.payload);
	ses.payload = NULL;

	TRACE(("leave process_packet"));
}

/* process a packet, and also check that auth has been done */
static void svr_process_postauth_packet(unsigned int type) {

	/* messages following here require userauth before use */

	/* IF YOU ADD MORE PACKET TYPES, MAKE SURE THEY'RE ALSO ADDED TO THE LIST
	 * IN process_packet() XXX XXX XXX */
	if (!svr_ses.authstate.authdone) {
		dropbear_exit("received message %d before userauth", type);
	}

	switch (type) {

		case SSH_MSG_CHANNEL_DATA:
			recv_msg_channel_data();
			break;

		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
			recv_msg_channel_window_adjust();
			break;

#ifndef DISABLE_REMOTETCPFWD
		case SSH_MSG_GLOBAL_REQUEST:
			/* currently only used for remote tcp, so we cheat a little */
			recv_msg_global_request_remotetcp();
			break;
#endif

		case SSH_MSG_CHANNEL_REQUEST:
			recv_msg_channel_request();
			break;

		case SSH_MSG_CHANNEL_OPEN:
			recv_msg_channel_open();
			break;

		case SSH_MSG_CHANNEL_EOF:
			recv_msg_channel_eof();
			break;

		case SSH_MSG_CHANNEL_CLOSE:
			recv_msg_channel_close();
			break;

#ifdef USING_LISTENERS /* for x11, tcp fwd etc */
		case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
			recv_msg_channel_open_confirmation();
			break;
			
		case SSH_MSG_CHANNEL_OPEN_FAILURE:
			recv_msg_channel_open_failure();
			break;
#endif
			
		default:
			TRACE(("unknown packet()"));
			recv_unimplemented();
			break;
	}
}
