/*
 * Dropbear - a SSH2 server
 * SSH client implementation
 *
 * This code is copied from the larger file "kex.c" 
 * some functions are verbatim, others are generalized --mihnea
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * Portions Copyright (c) 2004 by Mihnea Stoenescu
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
#include "dbutil.h"
#include "algo.h"
#include "buffer.h"
#include "session.h"
#include "kex.h"
#include "ssh.h"
#include "packet.h"
#include "bignum.h"
#include "random.h"

/* diffie-hellman-group1-sha1 value for p */
const unsigned char dh_p_val[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
	0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
	0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
	0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
	0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
	0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
	0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
	0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

const int DH_G_VAL = 2;

static void gen_new_keys();
#ifndef DISABLE_ZLIB
static void gen_new_zstreams();
#endif
/* helper function for gen_new_keys */
static void hashkeys(unsigned char *out, int outlen, 
		const hash_state * hs, unsigned const char X);


/* Send our list of algorithms we can use */
void send_msg_kexinit() {

	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_KEXINIT);

	/* cookie */
	genrandom(buf_getwriteptr(ses.writepayload, 16), 16);
	buf_incrwritepos(ses.writepayload, 16);

	/* kex algos */
	buf_put_algolist(ses.writepayload, sshkex);

	/* server_host_key_algorithms */
	buf_put_algolist(ses.writepayload, sshhostkey);

	/* encryption_algorithms_client_to_server */
	buf_put_algolist(ses.writepayload, sshciphers);

	/* encryption_algorithms_server_to_client */
	buf_put_algolist(ses.writepayload, sshciphers);

	/* mac_algorithms_client_to_server */
	buf_put_algolist(ses.writepayload, sshhashes);

	/* mac_algorithms_server_to_client */
	buf_put_algolist(ses.writepayload, sshhashes);

	/* compression_algorithms_client_to_server */
	buf_put_algolist(ses.writepayload, sshcompress);

	/* compression_algorithms_server_to_client */
	buf_put_algolist(ses.writepayload, sshcompress);

	/* languages_client_to_server */
	buf_putstring(ses.writepayload, "", 0);

	/* languages_server_to_client */
	buf_putstring(ses.writepayload, "", 0);

	/* first_kex_packet_follows - unimplemented for now */
	buf_putbyte(ses.writepayload, 0x00);

	/* reserved unit32 */
	buf_putint(ses.writepayload, 0);

	/* set up transmitted kex packet buffer for hashing. 
	 * This is freed after the end of the kex */
	ses.transkexinit = buf_newcopy(ses.writepayload);

	encrypt_packet();
	ses.dataallowed = 0; /* don't send other packets during kex */

	TRACE(("DATAALLOWED=0"));
	TRACE(("-> KEXINIT"));
	ses.kexstate.sentkexinit = 1;
}

/* *** NOTE regarding (send|recv)_msg_newkeys *** 
 * Changed by mihnea from the original kex.c to set dataallowed after a 
 * completed key exchange, no matter the order in which it was performed.
 * This enables client mode without affecting server functionality.
 */

/* Bring new keys into use after a key exchange, and let the client know*/
void send_msg_newkeys() {

	TRACE(("enter send_msg_newkeys"));

	/* generate the kexinit request */
	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_NEWKEYS);
	encrypt_packet();
	

	/* set up our state */
	if (ses.kexstate.recvnewkeys) {
		TRACE(("while RECVNEWKEYS=1"));
		gen_new_keys();
		kexinitialise(); /* we've finished with this kex */
		TRACE((" -> DATAALLOWED=1"));
		ses.dataallowed = 1; /* we can send other packets again now */
	} else {
		ses.kexstate.sentnewkeys = 1;
		TRACE(("SENTNEWKEYS=1"));
	}

	TRACE(("-> MSG_NEWKEYS"));
	TRACE(("leave send_msg_newkeys"));
}

/* Bring the new keys into use after a key exchange */
void recv_msg_newkeys() {

	TRACE(("<- MSG_NEWKEYS"));
	TRACE(("enter recv_msg_newkeys"));

	/* simply check if we've sent SSH_MSG_NEWKEYS, and if so,
	 * switch to the new keys */
	if (ses.kexstate.sentnewkeys) {
		TRACE(("while SENTNEWKEYS=1"));
		gen_new_keys();
		kexinitialise(); /* we've finished with this kex */
	    TRACE((" -> DATAALLOWED=1"));
	    ses.dataallowed = 1; /* we can send other packets again now */
	} else {
		TRACE(("RECVNEWKEYS=1"));
		ses.kexstate.recvnewkeys = 1;
	}
	
	TRACE(("leave recv_msg_newkeys"));
}


/* Duplicated verbatim from kex.c --mihnea */
void kexinitialise() {

	struct timeval tv;

	TRACE(("kexinitialise()"));

	/* sent/recv'd MSG_KEXINIT */
	ses.kexstate.sentkexinit = 0;
	ses.kexstate.recvkexinit = 0;

	/* sent/recv'd MSG_NEWKEYS */
	ses.kexstate.recvnewkeys = 0;
	ses.kexstate.sentnewkeys = 0;

	/* first_packet_follows */
	/* TODO - currently not handled */
	ses.kexstate.firstfollows = 0;

	ses.kexstate.datatrans = 0;
	ses.kexstate.datarecv = 0;

	if (gettimeofday(&tv, 0) < 0) {
		dropbear_exit("Error getting time");
	}
	ses.kexstate.lastkextime = tv.tv_sec;

}

/* Helper function for gen_new_keys, creates a hash. It makes a copy of the
 * already initialised hash_state hs, which should already have processed
 * the dh_K and hash, since these are common. X is the letter 'A', 'B' etc.
 * out must have at least min(SHA1_HASH_SIZE, outlen) bytes allocated.
 * The output will only be expanded once, since that is all that is required
 * (for 3DES and SHA, with 24 and 20 bytes respectively). 
 *
 * See Section 5.2 of the IETF secsh Transport Draft for details */

/* Duplicated verbatim from kex.c --mihnea */
static void hashkeys(unsigned char *out, int outlen, 
		const hash_state * hs, const unsigned char X) {

	hash_state hs2;
	unsigned char k2[SHA1_HASH_SIZE]; /* used to extending */

	memcpy(&hs2, hs, sizeof(hash_state));
	sha1_process(&hs2, &X, 1);
	sha1_process(&hs2, ses.session_id, SHA1_HASH_SIZE);
	sha1_done(&hs2, out);
	if (SHA1_HASH_SIZE < outlen) {
		/* need to extend */
		memcpy(&hs2, hs, sizeof(hash_state));
		sha1_process(&hs2, out, SHA1_HASH_SIZE);
		sha1_done(&hs2, k2);
		memcpy(&out[SHA1_HASH_SIZE], k2, outlen - SHA1_HASH_SIZE);
	}
}

/* Generate the actual encryption/integrity keys, using the results of the
 * key exchange, as specified in section 5.2 of the IETF secsh-transport
 * draft. This occurs after the DH key-exchange.
 *
 * ses.newkeys is the new set of keys which are generated, these are only
 * taken into use after both sides have sent a newkeys message */

/* Originally from kex.c, generalized for cli/svr mode --mihnea */
static void gen_new_keys() {

	unsigned char C2S_IV[MAX_IV_LEN];
	unsigned char C2S_key[MAX_KEY_LEN];
	unsigned char S2C_IV[MAX_IV_LEN];
	unsigned char S2C_key[MAX_KEY_LEN];
	/* unsigned char key[MAX_KEY_LEN]; */
	unsigned char *trans_IV, *trans_key, *recv_IV, *recv_key;

	hash_state hs;
	unsigned int C2S_keysize, S2C_keysize;
	char mactransletter, macrecvletter; /* Client or server specific */

	TRACE(("enter gen_new_keys"));
	/* the dh_K and hash are the start of all hashes, we make use of that */

	sha1_init(&hs);
	sha1_process_mp(&hs, ses.dh_K);
	mp_clear(ses.dh_K);
	m_free(ses.dh_K);
	sha1_process(&hs, ses.hash, SHA1_HASH_SIZE);
	m_burn(ses.hash, SHA1_HASH_SIZE);

	hashkeys(C2S_IV, SHA1_HASH_SIZE, &hs, 'A');
	hashkeys(S2C_IV, SHA1_HASH_SIZE, &hs, 'B');

	if (IS_DROPBEAR_CLIENT) {
	    trans_IV	= C2S_IV;
	    recv_IV		= S2C_IV;
	    trans_key	= C2S_key;
	    recv_key	= S2C_key;
	    C2S_keysize = ses.newkeys->trans_algo_crypt->keysize;
	    S2C_keysize = ses.newkeys->recv_algo_crypt->keysize;
		mactransletter = 'E';
		macrecvletter = 'F';
	} else {
	    trans_IV	= S2C_IV;
	    recv_IV		= C2S_IV;
	    trans_key	= S2C_key;
	    recv_key	= C2S_key;
	    C2S_keysize = ses.newkeys->recv_algo_crypt->keysize;
	    S2C_keysize = ses.newkeys->trans_algo_crypt->keysize;
		mactransletter = 'F';
		macrecvletter = 'E';
	}

	hashkeys(C2S_key, C2S_keysize, &hs, 'C');
	hashkeys(S2C_key, S2C_keysize, &hs, 'D');

	if (cbc_start(
		find_cipher(ses.newkeys->recv_algo_crypt->cipherdesc->name),
			recv_IV, recv_key, 
			ses.newkeys->recv_algo_crypt->keysize, 0, 
			&ses.newkeys->recv_symmetric_struct) != CRYPT_OK) {
		dropbear_exit("crypto error");
	}

	if (cbc_start(
		find_cipher(ses.newkeys->trans_algo_crypt->cipherdesc->name),
			trans_IV, trans_key, 
			ses.newkeys->trans_algo_crypt->keysize, 0, 
			&ses.newkeys->trans_symmetric_struct) != CRYPT_OK) {
		dropbear_exit("crypto error");
	}
	
	/* MAC keys */
	hashkeys(ses.newkeys->transmackey, 
			ses.newkeys->trans_algo_mac->keysize, &hs, mactransletter);
	hashkeys(ses.newkeys->recvmackey, 
			ses.newkeys->recv_algo_mac->keysize, &hs, macrecvletter);

#ifndef DISABLE_ZLIB
	gen_new_zstreams();
#endif
	
	/* Switch over to the new keys */
	m_burn(ses.keys, sizeof(struct key_context));
	m_free(ses.keys);
	ses.keys = ses.newkeys;
	ses.newkeys = NULL;

	TRACE(("leave gen_new_keys"));
}

#ifndef DISABLE_ZLIB
/* Set up new zlib compression streams, close the old ones. Only
 * called from gen_new_keys() */
static void gen_new_zstreams() {

	/* create new zstreams */
	if (ses.newkeys->recv_algo_comp == DROPBEAR_COMP_ZLIB) {
		ses.newkeys->recv_zstream = (z_streamp)m_malloc(sizeof(z_stream));
		ses.newkeys->recv_zstream->zalloc = Z_NULL;
		ses.newkeys->recv_zstream->zfree = Z_NULL;
		
		if (inflateInit(ses.newkeys->recv_zstream) != Z_OK) {
			dropbear_exit("zlib error");
		}
	} else {
		ses.newkeys->recv_zstream = NULL;
	}

	if (ses.newkeys->trans_algo_comp == DROPBEAR_COMP_ZLIB) {
		ses.newkeys->trans_zstream = (z_streamp)m_malloc(sizeof(z_stream));
		ses.newkeys->trans_zstream->zalloc = Z_NULL;
		ses.newkeys->trans_zstream->zfree = Z_NULL;
	
		if (deflateInit(ses.newkeys->trans_zstream, Z_DEFAULT_COMPRESSION) 
				!= Z_OK) {
			dropbear_exit("zlib error");
		}
	} else {
		ses.newkeys->trans_zstream = NULL;
	}
	
	/* clean up old keys */
	if (ses.keys->recv_zstream != NULL) {
		if (inflateEnd(ses.keys->recv_zstream) == Z_STREAM_ERROR) {
			/* Z_DATA_ERROR is ok, just means that stream isn't ended */
			dropbear_exit("crypto error");
		}
		m_free(ses.keys->recv_zstream);
	}
	if (ses.keys->trans_zstream != NULL) {
		if (deflateEnd(ses.keys->trans_zstream) == Z_STREAM_ERROR) {
			/* Z_DATA_ERROR is ok, just means that stream isn't ended */
			dropbear_exit("crypto error");
		}
		m_free(ses.keys->trans_zstream);
	}
}
#endif


/* Executed upon receiving a kexinit message from the client to initiate
 * key exchange. If we haven't already done so, we send the list of our
 * preferred algorithms. The client's requested algorithms are processed,
 * and we calculate the first portion of the key-exchange-hash for used
 * later in the key exchange. No response is sent, as the client should
 * initiate the diffie-hellman key exchange */

/* Originally from kex.c, generalized for cli/svr mode --mihnea  */
/* Belongs in common_kex.c where it should be moved after review */
void recv_msg_kexinit() {
	
	TRACE(("<- KEXINIT"));
	TRACE(("enter recv_msg_kexinit"));
	
	/* start the kex hash */
	ses.kexhashbuf = buf_new(MAX_KEXHASHBUF);

	if (!ses.kexstate.sentkexinit) {
		/* we need to send a kex packet */
		send_msg_kexinit();
		TRACE(("continue recv_msg_kexinit: sent kexinit"));
	}


	if (IS_DROPBEAR_CLIENT) {

	/* read the peer's choice of algos */
		cli_read_kex();

	/* V_C, the client's version string (CR and NL excluded) */
	    buf_putstring(ses.kexhashbuf,
			(unsigned char*)LOCAL_IDENT, strlen(LOCAL_IDENT));
	/* V_S, the server's version string (CR and NL excluded) */
	    buf_putstring(ses.kexhashbuf, 
			ses.remoteident, strlen((char*)ses.remoteident));

	/* I_C, the payload of the client's SSH_MSG_KEXINIT */
	    buf_putstring(ses.kexhashbuf,
			buf_getptr(ses.transkexinit, ses.transkexinit->len),
			ses.transkexinit->len);
	/* I_S, the payload of the server's SSH_MSG_KEXINIT */
	    buf_setpos(ses.payload, 0);
	    buf_putstring(ses.kexhashbuf,
			buf_getptr(ses.payload, ses.payload->len),
			ses.payload->len);

	} else {

	/* read the peer's choice of algos */
		svr_read_kex();
	/* V_C, the client's version string (CR and NL excluded) */
	    buf_putstring(ses.kexhashbuf, 
			ses.remoteident, strlen((char*)ses.remoteident));
	/* V_S, the server's version string (CR and NL excluded) */
	    buf_putstring(ses.kexhashbuf,
			(unsigned char*)LOCAL_IDENT, strlen(LOCAL_IDENT));

	/* I_C, the payload of the client's SSH_MSG_KEXINIT */
	    buf_setpos(ses.payload, 0);
	    buf_putstring(ses.kexhashbuf,
			buf_getptr(ses.payload, ses.payload->len),
			ses.payload->len);
	/* I_S, the payload of the server's SSH_MSG_KEXINIT */
	    buf_putstring(ses.kexhashbuf,
			buf_getptr(ses.transkexinit, ses.transkexinit->len),
			ses.transkexinit->len);
	}

	buf_free(ses.transkexinit);
	ses.transkexinit = NULL;
	/* the rest of ses.kexhashbuf will be done after DH exchange */

	ses.kexstate.recvkexinit = 1;
//	ses.expecting = SSH_MSG_KEXDH_INIT;
	ses.expecting = 0;

	TRACE(("leave recv_msg_kexinit"));
}

