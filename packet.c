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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include "options.h"
#include "packet.h"
#include "session.h"
#include "util.h"
#include "ssh.h"
#include "algo.h"
#include "buffer.h"
#include "kex.h"
#include "random.h"
#include "service.h"
#include "auth.h"
#include "channel.h"
#include "libtomcrypt/mycrypt.h"

static void read_packet_init();
static void process_postauth_packet(unsigned int type);
static void recv_unimplemented();

#define ZLIB_COMPRESS_INCR 20 /* this is 12 bytes + 0.1% of 8000 bytes */
#define ZLIB_DECOMPRESS_INCR 100
#ifndef DISABLE_ZLIB
static buffer* buf_decompress(buffer* buf, unsigned int len);
static void buf_compress(buffer * dest, buffer * src, unsigned int len);
#endif

/* non-blocking function writing out a current encrypted packet */
void write_packet() {

	int len, written;
	buffer * writebuf;
	
	TRACE(("enter write_packet"));
	assert(!isempty(&ses.writequeue));

	writebuf = (buffer*)examine(&ses.writequeue);

	len = writebuf->len - writebuf->pos;
	assert(len > 0);
	written = write(ses.sock, buf_getptr(writebuf, len), len);

	if (written < 0) {
		if (errno == EINTR) {
			TRACE(("leave writepacket: EINTR"));
			return;
		} else {
			dropbear_exit("error writing");
		}
	} 

	if (written == 0) {
		dropbear_close("remote host closed connection");
	}

	if (written == len) {
		dequeue(&ses.writequeue);
		buf_free(writebuf);
	} else {
		buf_incrpos(writebuf, written);
	}

	TRACE(("leave write_packet"));
}

/* non-blocking function reading available portion of a packet into the
 * ses's buffer, decrypting the length if encrypted, decrypting the
 * full portion if possible */
void read_packet() {

	int len;
	unsigned int maxlen;
	unsigned char blocksize;

	TRACE(("enter read_packet"));
	blocksize = ses.keys->recv_algo_crypt->blocksize;
	
	if (ses.readbuf == NULL || ses.readbuf->len < blocksize) {
		/* don't know the packetsize since we haven't got the first block to
		 * decrypt */
		read_packet_init();
		/* we should return so that we can select(), to make sure that the
		 * next read won't return 0 simply because there are no more bytes */
		TRACE(("leave read_packet: packetinit done"));
		return;
	}

	assert(ses.readbuf != NULL);
	maxlen = ses.readbuf->len - ses.readbuf->pos;
	len = read(ses.sock, buf_getptr(ses.readbuf, maxlen), maxlen);
	buf_incrpos(ses.readbuf, len);

	if (len == 0) {
		dropbear_close("remote host closed connection");
	}

	if (len < 0) {
		if (errno == EINTR) {
			TRACE(("leave read_packet: EINTR"));
			return;
		} else {
			dropbear_exit("error reading");
		}
	}

	if (len == maxlen) {
		decrypt_packet();
		/* process_packet() will handle the packet from the main select loop */
	}
	TRACE(("leave read_packet"));
}

/* function used to read the initial portion of a packet, and determine the
 * length. Only called during the first BLOCKSIZE of a packet. */
static void read_packet_init() {

	unsigned int maxlen;
	int len;
	unsigned char blocksize;
	unsigned char macsize;


	blocksize = ses.keys->recv_algo_crypt->blocksize;
	macsize = ses.keys->recv_algo_mac->hashsize;

	if (ses.readbuf == NULL) {
		/* start of a new packet */
		ses.readbuf = buf_new(INIT_READBUF);
		assert(ses.decryptreadbuf == NULL);
		ses.decryptreadbuf = buf_new(blocksize);
	}

	maxlen = blocksize - ses.readbuf->pos;
			
	/* read the rest of the packet if possible */
	len = read(ses.sock, buf_getwriteptr(ses.readbuf, maxlen),
			maxlen);
	if (len == 0) {
		dropbear_close("remote host closed connection");
	}
	if (len < 0) {
		dropbear_exit("error reading");
	}

	buf_incrwritepos(ses.readbuf, len);
	if (len != maxlen) {
		/* don't have enough bytes to determine length, get next time */
		return;
	}

	/* now we have the first block, need to get packet length, so we decrypt
	 * the first block (only need first 4 bytes) */
	buf_setpos(ses.readbuf, 0);
	buf_setpos(ses.decryptreadbuf, 0);
	buf_setlen(ses.decryptreadbuf, 0);
	if (ses.keys->recv_algo_crypt->cipherdesc != NULL) {
		if (cbc_decrypt(buf_getptr(ses.readbuf, blocksize), 
					buf_getwriteptr(ses.decryptreadbuf,blocksize),
					&ses.keys->recv_symmetric_struct) != CRYPT_OK) {
			dropbear_exit("error decrypting");
		}
	} else {
		memcpy(buf_getwriteptr(ses.decryptreadbuf, blocksize), 
				buf_getptr(ses.readbuf, blocksize), blocksize);
	}
	buf_incrlen(ses.decryptreadbuf, blocksize);
	len = buf_getint(ses.decryptreadbuf) + 4 + macsize;

	buf_setpos(ses.readbuf, blocksize);

	/* check packet lengths */
	if (len > MAX_PACKET_LEN) {
		dropbear_exit("bad packet size");
	}
	if (len < MIN_PACKET_LEN + macsize) {
		dropbear_exit("bad packet size");
	}
	if ((len - macsize) % blocksize != 0) {
		dropbear_exit("bad packet size");
	}

	buf_resize(ses.readbuf, len);
	buf_setlen(ses.readbuf, len);

}

/* handle the received packet */
void decrypt_packet() {

	hmac_state hmac;
	unsigned char seqbuf[4];
	unsigned char blocksize;
	unsigned char macsize;
	unsigned int padlen;
	unsigned int len;
	unsigned char *recvmac;

	TRACE(("enter decrypt_packet"));
	blocksize = ses.keys->recv_algo_crypt->blocksize;
	macsize = ses.keys->recv_algo_mac->hashsize;

	ses.kexstate.datarecv += ses.readbuf->len;

	/* we've already decrypted the first blocksize in read_packet_init */
	buf_setpos(ses.readbuf, blocksize);

	buf_resize(ses.decryptreadbuf, ses.readbuf->len - macsize);
	buf_setlen(ses.decryptreadbuf, ses.decryptreadbuf->size);
	buf_setpos(ses.decryptreadbuf, blocksize);

	/* decrypt if encryption is set, memcpy otherwise */
	if (ses.keys->recv_algo_crypt->cipherdesc != NULL) {
		while (ses.readbuf->pos < ses.readbuf->len - macsize) {
			if (cbc_decrypt(buf_getptr(ses.readbuf, blocksize), 
						buf_getwriteptr(ses.decryptreadbuf, blocksize),
						&ses.keys->recv_symmetric_struct) != CRYPT_OK) {
				dropbear_exit("error decrypting");
			}
			buf_incrpos(ses.readbuf, blocksize);
			buf_incrwritepos(ses.decryptreadbuf, blocksize);
		}
	} else {
		/* no encryption */
		len = ses.readbuf->len - ses.decryptreadbuf->pos;
		memcpy(buf_getwriteptr(ses.decryptreadbuf, len),
				buf_getptr(ses.readbuf, len), len);
	}

	if (macsize > 0) {
		/* calculate the mac */
		if (hmac_init(&hmac, 
					find_hash(ses.keys->recv_algo_mac->hashdesc->name), 
					ses.keys->recvmackey, 
					ses.keys->recv_algo_mac->keysize) 
					!= CRYPT_OK) {
			dropbear_exit("HMAC error");
		}
	
		/* sequence number */
		STORE32H(ses.recvseq, seqbuf);
		if (hmac_process(&hmac, seqbuf, 4) != CRYPT_OK) {
			dropbear_exit("HMAC error");
		}
	
		buf_setpos(ses.decryptreadbuf, 0);
		len = ses.decryptreadbuf->len;
		if (hmac_process(&hmac, buf_getptr(ses.decryptreadbuf, len), len)
				!= CRYPT_OK) {
			dropbear_exit("HMAC error");
		}
	
		recvmac = (unsigned char*)m_malloc(macsize);
		if (hmac_done(&hmac, recvmac) != CRYPT_OK) {
			dropbear_exit("HMAC error");
		}
	
		/* compare the hash */
		buf_setpos(ses.readbuf, ses.readbuf->len - macsize);
		if (memcmp(recvmac, buf_getptr(ses.readbuf, macsize),
					macsize) != 0) {
			dropbear_exit("Integrity error");
		}
		m_free(recvmac);

	} /* hash */

	/* readbuf no longer required */
	buf_free(ses.readbuf);
	ses.readbuf = NULL;

	/* get padding length */
	buf_setpos(ses.decryptreadbuf, PACKET_PADDING_OFF);
	padlen = buf_getbyte(ses.decryptreadbuf);
		
	/* payload length */
	/* - 4 - 1 is for LEN and PADLEN values */
	len = ses.decryptreadbuf->len - padlen - 4 - 1;
	if (len > MAX_PAYLOAD_LEN) {
		dropbear_exit("bad packet size");
	}
	if (len < 1) { /* this is valid? */
		dropbear_exit("bad packet size");
	}

	buf_setpos(ses.decryptreadbuf, PACKET_PAYLOAD_OFF);

#ifndef DISABLE_ZLIB
	if (ses.keys->recv_algo_comp == DROPBEAR_COMP_ZLIB) {
		/* decompress */
		ses.payload = buf_decompress(ses.decryptreadbuf, len);

	} else 
#endif
	{
		/* copy payload */
		ses.payload = buf_new(len);
		memcpy(ses.payload->data, buf_getptr(ses.decryptreadbuf, len),
				len);
		buf_incrlen(ses.payload, len);
	}

	buf_free(ses.decryptreadbuf);
	ses.decryptreadbuf = NULL;
	buf_setpos(ses.payload, 0);

	ses.recvseq++;

	TRACE(("leave decrypt_packet"));
}

#ifndef DISABLE_ZLIB
/* returns a pointer to a newly created buffer */
static buffer* buf_decompress(buffer* buf, unsigned int len) {

	int result;
	buffer * ret;
	z_streamp zstream;

	zstream = ses.keys->recv_zstream;
	ret = buf_new(len);

	zstream->avail_in = len;
	zstream->next_in = buf_getptr(buf, len);

	/* decompress the payload, incrementally resizing the output buffer */
	while (1) {

		zstream->avail_out = ret->size - ret->pos;
		zstream->next_out = buf_getwriteptr(ret, zstream->avail_out);

		result = inflate(zstream, Z_SYNC_FLUSH);

		buf_setlen(ret, ret->size - zstream->avail_out);
		buf_setpos(ret, ret->len);

		if (result != Z_BUF_ERROR && result != Z_OK) {
			dropbear_exit("zlib error");
		}

		if (zstream->avail_in == 0 &&
		   		(zstream->avail_out != 0 || result == Z_BUF_ERROR)) {
			/* we can only exit if avail_out hasn't all been used,
			 * and there's no remaining input */
			return ret;
		}

		if (zstream->avail_out == 0) {
			buf_resize(ret, ret->size + ZLIB_DECOMPRESS_INCR);
		}
	}
}
#endif


/* process a decrypted packet, call the appropriate handler */
void process_packet() {

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

	/* check that we aren't expecting a particular packet */
	if (ses.expecting && ses.expecting != type) {
		/* TODO be more verbose, send disconnect? */
		dropbear_exit("unexpected packet type %d", type);
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

		case SSH_MSG_CHANNEL_DATA:
		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
		case SSH_MSG_CHANNEL_REQUEST:
		case SSH_MSG_CHANNEL_OPEN:
		case SSH_MSG_CHANNEL_EOF:
		case SSH_MSG_CHANNEL_CLOSE:
			/* these should be checked for authdone below */
			process_postauth_packet(type);
			break;
	
		default:
			/* TODO this possibly should be handled */
			TRACE(("unknown packet"));
			recv_unimplemented();
			break;
	}

out:
	buf_free(ses.payload);
	ses.payload = NULL;

	TRACE(("leave process_packet"));
}

/* process a packet, and also check that auth has been done */
static void process_postauth_packet(unsigned int type) {

	/* messages following here require userauth before use */
	if (!ses.authstate.authdone) {
		dropbear_exit("received message %d before userauth", type);
	}

	switch (type) {

		case SSH_MSG_CHANNEL_DATA:
			recv_msg_channel_data();
			break;

		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
			recv_msg_channel_window_adjust();
			break;

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
			
		default:
			TRACE(("unknown packet()"));
			recv_unimplemented();
			break;
	}
}

/* This must be called directly after receiving the unimplemented packet.
 * Isn't the most clean implementation, it relies on packet processing
 * occurring directly after decryption. This is reasonably valid, since
 * there is only a single decryption buffer */
static void recv_unimplemented() {

	unsigned int seq;

	/* the decryption routine increments the sequence number, we must
	 * decrement */
	seq = ses.recvseq - 1;

	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_UNIMPLEMENTED);
	buf_putint(ses.writepayload, seq);

	encrypt_packet();
}
	


/* encrypt the writepayload, putting into writebuf, ready for write_packet()
 * to put on the wire */
void encrypt_packet() {

	unsigned char padlen;
	unsigned char blocksize, macsize;
	hmac_state hmac;
	unsigned char seqbuf[4];
	buffer * writebuf; /* the packet which will go on the wire */
	buffer * clearwritebuf; /* unencrypted, possibly compressed */
	
	TRACE(("enter encrypt_packet()"));
	TRACE(("encrypt_packet type is %d", ses.writepayload->data[0]));
	blocksize = ses.keys->trans_algo_crypt->blocksize;
	macsize = ses.keys->trans_algo_mac->hashsize;

	/* packet encrypted len is payload+5, then worst case is if we are 3 away
	 * from a blocksize multiple, in which case we need to pad to the
	 * multiple, then add another blocksize (or MIN_PACKET_LEN) */
	clearwritebuf = buf_new((ses.writepayload->len+4+1) + MIN_PACKET_LEN + 3
#ifndef DISABLE_ZLIB
			+ ZLIB_COMPRESS_INCR /* bit of a kludge, but we can't know len*/
#endif
			);
	buf_setlen(clearwritebuf, PACKET_PAYLOAD_OFF);
	buf_setpos(clearwritebuf, PACKET_PAYLOAD_OFF);

	buf_setpos(ses.writepayload, 0);

#ifndef DISABLE_ZLIB
	/* compression */
	if (ses.keys->trans_algo_comp == DROPBEAR_COMP_ZLIB) {
		buf_compress(clearwritebuf, 
					ses.writepayload, ses.writepayload->len);
	} else
#endif
	{
		memcpy(buf_getwriteptr(clearwritebuf, ses.writepayload->len),
				buf_getptr(ses.writepayload, ses.writepayload->len),
				ses.writepayload->len);
		buf_incrwritepos(clearwritebuf, ses.writepayload->len);
	}

	/* finished with payload */
	buf_setpos(ses.writepayload, 0);
	buf_setlen(ses.writepayload, 0);

	/* length of padding */
	padlen = blocksize - (clearwritebuf->len) % blocksize;
	if (padlen < 4) {
		padlen += blocksize;
	}
	/* check for min packet length */
	if (clearwritebuf->len + padlen < MIN_PACKET_LEN) {
		padlen += blocksize;
	}

	buf_setpos(clearwritebuf, 0);
	/* packet length excl the packetlen uint32 */
	buf_putint(clearwritebuf, clearwritebuf->len + padlen - 4);

	/* padding len */
	buf_putbyte(clearwritebuf, padlen);
	/* actual padding */
	buf_setpos(clearwritebuf, clearwritebuf->len);
	buf_incrlen(clearwritebuf, padlen);
	genrandom(buf_getptr(clearwritebuf, padlen), padlen);

	/* do the actual encryption */
	buf_setpos(clearwritebuf, 0);
	/* create a new writebuffer, this is freed when it has been put on the 
	 * wire by writepacket() */
	writebuf = buf_new(clearwritebuf->len + macsize);

	if (ses.keys->trans_algo_crypt->cipherdesc != NULL) {
		/* encrypt it */
		while (clearwritebuf->pos < clearwritebuf->len) {
			if (cbc_encrypt(buf_getptr(clearwritebuf, blocksize),
						buf_getwriteptr(writebuf, blocksize),
						&ses.keys->trans_symmetric_struct) != CRYPT_OK) {
				dropbear_exit("error encrypting");
			}
			buf_incrpos(clearwritebuf, blocksize);
			buf_incrwritepos(writebuf, blocksize);
		}
	} else {
		/* no encryption */
		memcpy(buf_getwriteptr(writebuf, clearwritebuf->len),
			buf_getptr(clearwritebuf, clearwritebuf->len),
					clearwritebuf->len);
		buf_incrwritepos(writebuf, clearwritebuf->len);
	}


	/* now add a hmac and we're done */
	if (macsize > 0) {
		/* calculate the mac */
		if (hmac_init(&hmac, 
					find_hash(ses.keys->trans_algo_mac->hashdesc->name), 
					ses.keys->transmackey, 
					ses.keys->trans_algo_mac->keysize) != CRYPT_OK) {
			dropbear_exit("HMAC error");
		}
	
		/* sequence number */
		STORE32H(ses.transseq, seqbuf);
		if (hmac_process(&hmac, seqbuf, 4) != CRYPT_OK) {
			dropbear_exit("HMAC error");
		}
	
		/* the actual contents */
		buf_setpos(clearwritebuf, 0);
		if (hmac_process(&hmac, 
					buf_getptr(clearwritebuf, 
						clearwritebuf->len),
					clearwritebuf->len) != CRYPT_OK) {
			dropbear_exit("HMAC error");
		}
	
		if (hmac_done(&hmac, buf_getwriteptr(writebuf, macsize)) 
				!= CRYPT_OK) {
			dropbear_exit("HMAC error");
		}
		buf_incrlen(writebuf, macsize);
	
	} /* hash */

	/* clearwritebuf is finished with */
	buf_free(clearwritebuf);

	ses.transseq++;

	buf_setpos(writebuf, 0);
	enqueue(&ses.writequeue, (void*)writebuf);

	ses.kexstate.datatrans += writebuf->len;

	TRACE(("leave encrypt_packet()"));
}

#ifndef DISABLE_ZLIB
/* compresses len bytes from src, outputting to dest (starting from the
 * respective current positions. */
static void buf_compress(buffer * dest, buffer * src, unsigned int len) {

	unsigned int endpos = src->pos + len;
	int result;

	TRACE(("enter buf_compress"));

	while (1) {

		ses.keys->trans_zstream->avail_in = endpos - src->pos;
		ses.keys->trans_zstream->next_in = 
			buf_getptr(src, ses.keys->trans_zstream->avail_in);

		ses.keys->trans_zstream->avail_out = dest->size - dest->pos;
		ses.keys->trans_zstream->next_out =
			buf_getwriteptr(dest, ses.keys->trans_zstream->avail_out);

		result = deflate(ses.keys->trans_zstream, Z_SYNC_FLUSH);

		buf_setpos(src, endpos - ses.keys->trans_zstream->avail_in);
		buf_setlen(dest, dest->size - ses.keys->trans_zstream->avail_out);
		buf_setpos(dest, dest->len);

		if (result != Z_OK) {
			dropbear_exit("zlib error");
		}

		if (ses.keys->trans_zstream->avail_in == 0) {
			break;
		}

		assert(ses.keys->trans_zstream->avail_out == 0);
		buf_resize(dest, ZLIB_COMPRESS_INCR);

	}
	TRACE(("leave buf_compress"));
}
#endif


