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
#include "listener.h"

extern int sessinitdone; /* Is set to 0 somewhere */
extern int exitflag;

void common_session_init(int sock, runopts *opts);
void common_session_cleanup();
void checktimeouts();
void session_identification();

extern void(*session_remoteclosed)();

/* Server */
void svr_session(int sock, runopts *opts, int childpipe,
		struct sockaddr *remoteaddr);
void svr_dropbear_exit(int exitcode, const char* format, va_list param);
void svr_dropbear_log(int priority, const char* format, va_list param);


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

	/* Is it a client or server? */
	unsigned char isserver;

	runopts * opts; /* runtime options, incl hostkey, banner etc */

	long connecttimeout; /* time to disconnect if we have a timeout (for
							userauth etc), or 0 for no timeout */

	int sock;

	struct sockaddr *remoteaddr;
	unsigned char *remotehost; /* the peer hostname */
	unsigned char *remoteident;

	int maxfd; /* the maximum file descriptor to check with select() */


	/* Packet buffers/values etc */
	buffer *writepayload; /* Unencrypted payload to write - this is used
							 throughout the code, as handlers fill out this
							 buffer with the packet to send. */
	struct Queue writequeue; /* A queue of encrypted packets to send */
	buffer *readbuf; /* Encrypted */
	buffer *decryptreadbuf; /* Post-decryption */
	buffer *payload; /* Post-decompression, the actual SSH packet */
	unsigned int transseq, recvseq; /* Sequence IDs */

	/* Packet-handling flags */
	unsigned dataallowed : 1; /* whether we can send data packets or we are in
								 the middle of a KEX or something */

	unsigned char expecting; /* byte indicating what packet we expect next, 
								or 0x00 for any */

	unsigned char ignorenext; /* whether to ignore the next packet,
								 used for kex_follows stuff */
	


	/* KEX/encryption related */
	struct KEXState kexstate;
	struct key_context *keys;
	struct key_context *newkeys;
	unsigned char *session_id; /* this is the hash from the first kex */
	/* The below are used temorarily during kex, are freed after use */
	mp_int * dh_K; /* SSH_MSG_KEXDH_REPLY and sending SSH_MSH_NEWKEYS */
	unsigned char hash[SHA1_HASH_SIZE]; /* the hash*/
	buffer* kexhashbuf; /* session hash buffer calculated from various packets*/
	buffer* transkexinit; /* the kexinit packet we send should be kept so we
							 can add it to the hash when generating keys */



	/* Channel related */
	struct Channel ** channels; /* these pointers may be null */
	unsigned int chansize; /* the number of Channel*s allocated for channels */
	const struct ChanType **chantypes; /* The valid channel types */

	
	/* TCP forwarding - where manage listeners */
#ifndef DISABLE_REMOTETCPFWD
	struct Listener ** listeners;
	unsigned int listensize;
#endif

};

struct serversession {

	/* Server specific options */
	int childpipe; /* kept open until we successfully authenticate */
	/* userauth */
	struct AuthState authstate;

	struct ChildPid * childpids; /* array of mappings childpid<->channel */
	unsigned int childpidsize;

};



struct clientsession {

	int something; /* XXX */

};

/* Global structs storing the state */
extern struct sshsession ses;

#ifdef DROPBEAR_SERVER
extern struct serversession svr_ses;
#endif /* DROPBEAR_SERVER */

#ifdef DROPBEAR_CLIENT
extern struct serversession cli_ses;
#endif /* DROPBEAR_CLIENT */

#endif /* _SESSION_H_ */
