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

#ifndef _SESSION_H_
#define _SESSION_H_

#include "includes.h"
#include "buffer.h"
#include "signkey.h"
#include "kex.h"
#include "auth.h"
#include "channel.h"
#include "queue.h"
#include "runopts.h"

extern int sessinitdone;
extern int exitflag;

void session_cleanup();
void child_session(int sock, runopts *opts, int childpipe,
		struct sockaddr *remoteaddr);
void session_remoteclosed();

struct key_context {

	const struct dropbear_cipher *recv_algo_crypt; /* NULL for none */
	const struct dropbear_cipher *trans_algo_crypt; /* NULL for none */
	const struct dropbear_hash *recv_algo_mac; /* NULL for none */
	const struct dropbear_hash *trans_algo_mac; /* NULL for none */
	char algo_kex;
	char algo_hostkey;

	char recv_algo_comp; /* compression */
	char trans_algo_comp;
#ifndef DISABLE_ZLIB
	z_streamp recv_zstream;
	z_streamp trans_zstream;
#endif

	/* actual keys */
	symmetric_CBC recv_symmetric_struct;
	symmetric_CBC trans_symmetric_struct;
	unsigned char recvmackey[MAX_MAC_KEY];
	unsigned char transmackey[MAX_MAC_KEY];

};

struct sshsession {

	runopts * opts; /* runtime options, incl hostkey, banner etc */
	int sock;
	int childpipe; /* kept open until we successfully authenticate */
	long connecttime; /* time of initial connection */

	struct sockaddr *remoteaddr; /* the host and port of the client */
	unsigned char *addrstring; /* the text version of remoteaddr */
	unsigned char *hostname; /* the remote hostname */

	int maxfd; /* the maximum file descriptor to check with select() */
	unsigned char *remoteident;

	struct KEXState kexstate;

	/* flags */
	unsigned dataallowed : 1; /* whether we can send data packets or we are in
								 the middle of a KEX or something */

	unsigned char expecting; /* byte indicating what packet we expect next, 
								or 0x00 for any */
	
	/* unencrypted write payload */
	buffer *writepayload; /* this will actually refer to within clearwritebuf */
	unsigned int transseq; /* sequence number */
	/* encrypted write packet buffer queue */
	struct Queue writequeue;

	/* read packet buffer */
	buffer *readbuf;
	/* decrypted read buffer */
	buffer *decryptreadbuf;
	buffer *payload; /* this actually refers to within decryptreadbuf */
	unsigned int recvseq; /* sequence number */

	struct key_context *keys;
	struct key_context *newkeys;
	
	unsigned char *session_id; /*this is the hash from the first kex*/

	/* the following are for key exchange */
	unsigned char hash[SHA1_HASH_SIZE]; /* the hash*/
	/* these are used temorarily during kex, are freed after use */
	mp_int * dh_K; /* SSH_MSG_KEXDH_REPLY and sending SSH_MSH_NEWKEYS */
	buffer* kexhashbuf; /* session hash buffer calculated from various packets*/
	buffer* transkexinit; /* the kexinit payload we send */

	/* userauth */
	struct AuthState authstate;

	/* channels */
	struct Channel ** channels; /* these pointers may be null */
	unsigned int chansize; /* the number of Channel*s allocated for channels */

	struct ChildPid * childpids; /* array of mappings childpid<->channel */
	unsigned int childpidsize;

};

/* global struct storing the state */
extern struct sshsession ses;

#endif /* _SESSION_H_ */
