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

static void read_packet_init();
static void process_postauth_packet(unsigned int type);
static void recv_unimplemented();
static void writemac(buffer * outputbuffer, buffer * clearwritebuf);
static int checkmac(buffer* hashbuf, buffer* readbuf);

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

	/* Get the next buffer in the queue of encrypted packets to write*/
	writebuf = (buffer*)examine(&ses.writequeue);

	len = writebuf->len - writebuf->pos;
	assert(len > 0);
	/* Try to write as much as possible */
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
		session_remoteclosed();
	}

	if (written == len) {
		/* We've finished with the packet, free it */
		dequeue(&ses.writequeue);
		buf_free(writebuf);
	} else {
		/* More packet left to write, leave it in the queue for later */
		buf_incrpos(writebuf, written);
	}

	TRACE(("leave write_packet"));
}

/* Non-blocking function reading available portion of a packet into the
 * ses's buffer, decrypting the length if encrypted, decrypting the
 * full portion if possible */
void read_packet() {

	int len;
	unsigned int maxlen;
	unsigned char blocksize;

	TRACE(("enter read_packet"));
	blocksize = ses.keys->recv_algo_crypt->blocksize;
	
	if (ses.readbuf == NULL || ses.readbuf->len < blocksize) {
		/* In the first blocksize of a packet */

		/* Read the first blocksize of the packet, so we can decrypt it and
		 * find the length of the whole packet */
		read_packet_init();

		/* If we don't have the length of decryptreadbuf, we didn't read
		 * a whole blocksize and should exit */
		if (ses.decryptreadbuf->len == 0) {
			TRACE(("leave read_packet: packetinit done"));
			return;
		}
	}

	/* Attempt to read the remainder of the packet, note that there
	 * mightn't be any available (EAGAIN) */
	assert(ses.readbuf != NULL);
	maxlen = ses.readbuf->len - ses.readbuf->pos;
	len = read(ses.sock, buf_getptr(ses.readbuf, maxlen), maxlen);
	buf_incrpos(ses.readbuf, len);

	if (len == 0) {
		session_remoteclosed();
	}

	if (len < 0) {
		if (errno == EINTR || errno == EAGAIN) {
			TRACE(("leave read_packet: EINTR or EAGAIN"));
			return;
		} else {
			dropbear_exit("error reading: %s", strerror(errno));
		}
	}

	if ((unsigned int)len == maxlen) {
		/* The whole packet has been read */
		decrypt_packet();
		/* The main select() loop in session.h will process_packet() to
		 * handle the packet contents... */
	}
	TRACE(("leave read_packet"));
}

/* Function used to read the initial portion of a packet, and determine the
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
		session_remoteclosed();
	}
	if (len < 0) {
		if (errno == EINTR) {
			TRACE(("leave read_packet_init: EINTR"));
			return;
		}
		dropbear_exit("error reading: %s", strerror(errno));
	}

	buf_incrwritepos(ses.readbuf, len);

	if ((unsigned int)len != maxlen) {
		/* don't have enough bytes to determine length, get next time */
		return;
	}

	/* now we have the first block, need to get packet length, so we decrypt
	 * the first block (only need first 4 bytes) */
	buf_setpos(ses.readbuf, 0);
	if (ses.keys->recv_algo_crypt->cipherdesc == NULL) {
		/* copy it */
		memcpy(buf_getwriteptr(ses.decryptreadbuf, blocksize),
				buf_getptr(ses.readbuf, blocksize),
				blocksize);
	} else {
		/* decrypt it */
		if (cbc_decrypt(buf_getptr(ses.readbuf, blocksize), 
					buf_getwriteptr(ses.decryptreadbuf,blocksize),
					&ses.keys->recv_symmetric_struct) != CRYPT_OK) {
			dropbear_exit("error decrypting");
		}
	}
	buf_setlen(ses.decryptreadbuf, blocksize);
	len = buf_getint(ses.decryptreadbuf) + 4 + macsize;

	buf_setpos(ses.readbuf, blocksize);

	/* check packet length */
	if ((len > MAX_PACKET_LEN) ||
		(len < MIN_PACKET_LEN + macsize) ||
		((len - macsize) % blocksize != 0)) {
		dropbear_exit("bad packet size");
	}

	buf_resize(ses.readbuf, len);
	buf_setlen(ses.readbuf, len);

}

/* handle the received packet */
void decrypt_packet() {

	unsigned char blocksize;
	unsigned char macsize;
	unsigned int padlen;
	unsigned int len;

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
	if (ses.keys->recv_algo_crypt->cipherdesc == NULL) {
		/* copy it */
		len = ses.readbuf->len - macsize - blocksize;
		memcpy(buf_getwriteptr(ses.decryptreadbuf, len),
				buf_getptr(ses.readbuf, len), len);
	} else {
		/* decrypt */
		while (ses.readbuf->pos < ses.readbuf->len - macsize) {
			if (cbc_decrypt(buf_getptr(ses.readbuf, blocksize), 
						buf_getwriteptr(ses.decryptreadbuf, blocksize),
						&ses.keys->recv_symmetric_struct) != CRYPT_OK) {
				dropbear_exit("error decrypting");
			}
			buf_incrpos(ses.readbuf, blocksize);
			buf_incrwritepos(ses.decryptreadbuf, blocksize);
		}
	}

	/* check the hmac */
	buf_setpos(ses.readbuf, ses.readbuf->len - macsize);
	if (checkmac(ses.readbuf, ses.decryptreadbuf) != DROPBEAR_SUCCESS) {
		dropbear_exit("Integrity error");
	}

	/* readbuf no longer required */
	buf_free(ses.readbuf);
	ses.readbuf = NULL;

	/* get padding length */
	buf_setpos(ses.decryptreadbuf, PACKET_PADDING_OFF);
	padlen = buf_getbyte(ses.decryptreadbuf);
		
	/* payload length */
	/* - 4 - 1 is for LEN and PADLEN values */
	len = ses.decryptreadbuf->len - padlen - 4 - 1;
	if ((len > MAX_PAYLOAD_LEN) || (len < 1)) {
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
		memcpy(ses.payload->data, buf_getptr(ses.decryptreadbuf, len), len);
		buf_incrlen(ses.payload, len);
	}

	buf_free(ses.decryptreadbuf);
	ses.decryptreadbuf = NULL;
	buf_setpos(ses.payload, 0);

	ses.recvseq++;

	TRACE(("leave decrypt_packet"));
}

/* Checks the mac in hashbuf, for the data in readbuf.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int checkmac(buffer* macbuf, buffer* sourcebuf) {

	unsigned char macsize;
	hmac_state hmac;
	unsigned char tempbuf[MAX_MAC_LEN];
	unsigned long hashsize;
	int len;

	macsize = ses.keys->recv_algo_mac->hashsize;

	if (macsize == 0) {
		return DROPBEAR_SUCCESS;
	}

	/* calculate the mac */
	if (hmac_init(&hmac, 
				find_hash(ses.keys->recv_algo_mac->hashdesc->name), 
				ses.keys->recvmackey, 
				ses.keys->recv_algo_mac->keysize) 
				!= CRYPT_OK) {
		dropbear_exit("HMAC error");
	}
	
	/* sequence number */
	STORE32H(ses.recvseq, tempbuf);
	if (hmac_process(&hmac, tempbuf, 4) != CRYPT_OK) {
		dropbear_exit("HMAC error");
	}

	buf_setpos(sourcebuf, 0);
	len = sourcebuf->len;
	if (hmac_process(&hmac, buf_getptr(sourcebuf, len), len) != CRYPT_OK) {
		dropbear_exit("HMAC error");
	}

	hashsize = sizeof(tempbuf);
	if (hmac_done(&hmac, tempbuf, &hashsize) != CRYPT_OK) {
		dropbear_exit("HMAC error");
	}

	/* compare the hash */
	if (memcmp(tempbuf, buf_getptr(macbuf, macsize), macsize) != 0) {
		return DROPBEAR_FAILURE;
	} else {
		return DROPBEAR_SUCCESS;
	}
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

#ifdef USE_LISTENERS /* for x11, tcp fwd etc */
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

/* This must be called directly after receiving the unimplemented packet.
 * Isn't the most clean implementation, it relies on packet processing
 * occurring directly after decryption. This is reasonably valid, since
 * there is only a single decryption buffer */
static void recv_unimplemented() {

	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_UNIMPLEMENTED);
	/* the decryption routine increments the sequence number, we must
	 * decrement */
	buf_putint(ses.writepayload, ses.recvseq - 1);

	encrypt_packet();
}
	


/* encrypt the writepayload, putting into writebuf, ready for write_packet()
 * to put on the wire */
void encrypt_packet() {

	unsigned char padlen;
	unsigned char blocksize, macsize;
	buffer * writebuf; /* the packet which will go on the wire */
	buffer * clearwritebuf; /* unencrypted, possibly compressed */
	
	TRACE(("enter encrypt_packet()"));
	TRACE(("encrypt_packet type is %d", ses.writepayload->data[0]));
	blocksize = ses.keys->trans_algo_crypt->blocksize;
	macsize = ses.keys->trans_algo_mac->hashsize;

	/* Encrypted packet len is payload+5, then worst case is if we are 3 away
	 * from a blocksize multiple. In which case we need to pad to the
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
		buf_compress(clearwritebuf, ses.writepayload, ses.writepayload->len);
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

	/* length of padding - packet length must be a multiple of blocksize,
	 * with a minimum of 4 bytes of padding */
	padlen = blocksize - (clearwritebuf->len) % blocksize;
	if (padlen < 4) {
		padlen += blocksize;
	}
	/* check for min packet length */
	if (clearwritebuf->len + padlen < MIN_PACKET_LEN) {
		padlen += blocksize;
	}

	buf_setpos(clearwritebuf, 0);
	/* packet length excluding the packetlength uint32 */
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

	if (ses.keys->trans_algo_crypt->cipherdesc == NULL) {
		/* copy it */
		memcpy(buf_getwriteptr(writebuf, clearwritebuf->len),
				buf_getptr(clearwritebuf, clearwritebuf->len),
				clearwritebuf->len);
		buf_incrwritepos(writebuf, clearwritebuf->len);
	} else {
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
	}

	/* now add a hmac and we're done */
	writemac(writebuf, clearwritebuf);

	/* clearwritebuf is finished with */
	buf_free(clearwritebuf);

	/* enqueue the packet for sending */
	buf_setpos(writebuf, 0);
	enqueue(&ses.writequeue, (void*)writebuf);

	/* Update counts */
	ses.kexstate.datatrans += writebuf->len;
	ses.transseq++;

	TRACE(("leave encrypt_packet()"));
}


/* Create the packet mac, and append H(seqno|clearbuf) to the output */
static void writemac(buffer * outputbuffer, buffer * clearwritebuf) {

	int macsize;
	unsigned char seqbuf[4];
	unsigned long hashsize;
	hmac_state hmac;

	TRACE(("enter writemac"));

	macsize = ses.keys->trans_algo_mac->hashsize;

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
	
		hashsize = macsize;
		if (hmac_done(&hmac, buf_getwriteptr(outputbuffer, macsize), &hashsize) 
				!= CRYPT_OK) {
			dropbear_exit("HMAC error");
		}
		buf_incrwritepos(outputbuffer, macsize);
	}
	TRACE(("leave writemac"));
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

		/* the buffer has been filled, we must extend. This only happens in
		 * unusual circumstances where the data grows in size after deflate(),
		 * but it is possible */
		buf_resize(dest, dest->size + ZLIB_COMPRESS_INCR);

	}
	TRACE(("leave buf_compress"));
}
#endif
