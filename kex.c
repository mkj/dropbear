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
#include "dbutil.h"
#include "algo.h"
#include "buffer.h"
#include "session.h"
#include "kex.h"
#include "ssh.h"
#include "packet.h"
#include "bignum.h"
#include "random.h"

/* diffie-hellman-group1-sha1 values for g and p */
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
#define DH_P_LEN 128

const unsigned int dh_g_val = 2;

static void read_kex();
static void gen_new_keys();
static void gen_new_zstreams();
/* helper function for gen_new_keys */
static void hashkeys(unsigned char *out, int outlen, 
		const hash_state * hs, unsigned const char X);
static void send_msg_kexdh_reply(mp_int *dh_e);

/* Executed upon receiving a kexinit message from the client to initiate
 * key exchange. If we haven't already done so, we send the list of our
 * preferred algorithms. The client's requested algorithms are processed,
 * and we calculate the first portion of the key-exchange-hash for used
 * later in the key exchange. No response is sent, as the client should
 * initiate the diffie-hellman key exchange */
void recv_msg_kexinit() {
	
	TRACE(("enter recv_msg_kexinit"));
	
	if (!ses.kexstate.sentkexinit) {
		/* we need to send a kex packet */
		send_msg_kexinit();
		TRACE(("continue recv_msg_kexinit: sent kexinit"));
	}

	/* read the client's choice of algos */
	read_kex();

	/* start the kex hash */
	ses.kexhashbuf = buf_new(MAX_KEXHASHBUF);
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
	buf_free(ses.transkexinit);
	ses.transkexinit = NULL;
	/* the rest of ses.kexhashbuf will be done after DH exchange */

	ses.kexstate.recvkexinit = 1;
	ses.expecting = SSH_MSG_KEXDH_INIT;

	TRACE(("leave recv_msg_kexinit"));
}

/* Bring new keys into use after a key exchange, and let the client know*/
void send_msg_newkeys() {

	TRACE(("enter send_msg_newkeys"));

	/* generate the kexinit request */
	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_NEWKEYS);
	encrypt_packet();
	

	/* set up our state */
	if (ses.kexstate.recvnewkeys) {
		gen_new_keys();
		kexinitialise(); /* we've finished with this kex */
	} else {
		ses.kexstate.sentnewkeys = 1;
	}

	TRACE(("leave send_msg_newkeys"));
}

/* Bring the new keys into use after a key exchange */
void recv_msg_newkeys() {

	TRACE(("enter recv_msg_newkeys"));

	/* simply check if we've sent SSH_MSG_NEWKEYS, and if so,
	 * switch to the new keys */
	if (ses.kexstate.sentnewkeys) {
		gen_new_keys();
		kexinitialise(); /* we've finished with this kex */
	} else {
		ses.kexstate.recvnewkeys = 1;
	}

	ses.dataallowed = 1; /* we can send other packets again now */
	TRACE(("leave recv_msg_newkeys"));
}

/* Set the kex state variables to initial values, ready to receive a new
 * SSH_MSG_KEXINIT (or send one) */
void kexinitialise() {

	struct timeval tv;

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
static void gen_new_keys() {

	unsigned char IV[MAX_IV_LEN];
	unsigned char key[MAX_KEY_LEN];
	hash_state hs;
	unsigned int keysize;

	TRACE(("enter gen_new_keys"));
	/* the dh_K and hash are the start of all hashes, we make use of that */
	sha1_init(&hs);
	sha1_process_mp(&hs, ses.dh_K);
	mp_clear(ses.dh_K);
	m_free(ses.dh_K);
	sha1_process(&hs, ses.hash, SHA1_HASH_SIZE);
	m_burn(ses.hash, SHA1_HASH_SIZE);

	/* client->server IV */
	hashkeys(IV, SHA1_HASH_SIZE, &hs, 'A');

	/* client->server encryption key */
	keysize = ses.newkeys->recv_algo_crypt->keysize;
	hashkeys(key, keysize, &hs, 'C');
	if (cbc_start(
			find_cipher(ses.newkeys->recv_algo_crypt->cipherdesc->name),
			IV, key, keysize, 0, 
			&ses.newkeys->recv_symmetric_struct) != CRYPT_OK) {
		dropbear_exit("crypto error");
	}

	/* server->client IV */
	hashkeys(IV, SHA1_HASH_SIZE, &hs, 'B');

	/* server->client encryption key */
	keysize = ses.newkeys->trans_algo_crypt->keysize;
	hashkeys(key, keysize, &hs, 'D');
	if (cbc_start(
			find_cipher(ses.newkeys->trans_algo_crypt->cipherdesc->name),
			IV, key, keysize, 0, 
			&ses.newkeys->trans_symmetric_struct) != CRYPT_OK) {
		dropbear_exit("crypto error");
	}
	/* MAC key client->server */
	keysize = ses.newkeys->recv_algo_mac->keysize;
	hashkeys(ses.newkeys->recvmackey, keysize, &hs, 'E');

	/* MAC key server->client */
	keysize = ses.newkeys->trans_algo_mac->keysize;
	hashkeys(ses.newkeys->transmackey, keysize, &hs, 'F');

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

/* Handle a diffie-hellman key exchange initialisation. This involves
 * calculating a session key reply value, and corresponding hash. These
 * are carried out by send_msg_kexdh_reply(). recv_msg_kexdh_init() calls
 * that function, then brings the new keys into use */
void recv_msg_kexdh_init() {

	mp_int dh_e;

	TRACE(("enter recv_msg_kexdh_init"));
	if (!ses.kexstate.recvkexinit) {
		dropbear_exit("Premature kexdh_init message received");
	}

	m_mp_init(&dh_e);
	buf_getmpint(ses.payload, &dh_e);

	send_msg_kexdh_reply(&dh_e);

	mp_clear(&dh_e);

	send_msg_newkeys();
	ses.expecting = SSH_MSG_NEWKEYS;
	TRACE(("leave recv_msg_kexdh_init"));
}
	
/* Generate our side of the diffie-hellman key exchange value (dh_f), and
 * calculate the session key using the diffie-hellman algorithm. Following
 * that, the session hash is calculated, and signed with RSA or DSS. The
 * result is sent to the client. 
 *
 * See the ietf-secsh-transport draft, section 6, for details */
static void send_msg_kexdh_reply(mp_int *dh_e) {

	mp_int dh_p, dh_q, dh_g, dh_y, dh_f;
	unsigned char randbuf[DH_P_LEN];
	int dh_q_len;
	hash_state hs;

	TRACE(("enter send_msg_kexdh_reply"));
	
	assert(ses.kexstate.recvkexinit);

	m_mp_init_multi(&dh_g, &dh_p, &dh_q, &dh_y, &dh_f, NULL);

	/* read the prime and generator*/
	if (mp_read_unsigned_bin(&dh_p, (unsigned char*)dh_p_val, DH_P_LEN)
			!= MP_OKAY) {
		dropbear_exit("Diffie-Hellman error");
	}
	
	if (mp_set_int(&dh_g, dh_g_val) != MP_OKAY) {
		dropbear_exit("Diffie-Hellman error");
	}

	/* calculate q = (p-1)/2 */
	if (mp_sub_d(&dh_p, 1, &dh_y) != MP_OKAY) { /*dh_y is just a temp var here*/
		dropbear_exit("Diffie-Hellman error");
	}
	if (mp_div_2(&dh_y, &dh_q) != MP_OKAY) {
		dropbear_exit("Diffie-Hellman error");
	}

	dh_q_len = mp_unsigned_bin_size(&dh_q);

	/* calculate our random value dh_y */
	do {
		assert((unsigned int)dh_q_len <= sizeof(randbuf));
		genrandom(randbuf, dh_q_len);
		if (mp_read_unsigned_bin(&dh_y, randbuf, dh_q_len) != MP_OKAY) {
			dropbear_exit("Diffie-Hellman error");
		}
	} while (mp_cmp(&dh_y, &dh_q) == MP_GT || mp_cmp_d(&dh_y, 0) != MP_GT);

	/* f = g^y mod p */
	if (mp_exptmod(&dh_g, &dh_y, &dh_p, &dh_f) != MP_OKAY) {
		dropbear_exit("Diffie-Hellman error");
	}
	mp_clear(&dh_g);

	/* K = e^y mod p */
	ses.dh_K = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(ses.dh_K);
	if (mp_exptmod(dh_e, &dh_y, &dh_p, ses.dh_K) != MP_OKAY) {
		dropbear_exit("Diffie-Hellman error");
	}

	/* clear no longer needed vars */
	mp_clear_multi(&dh_y, &dh_p, &dh_q, NULL);

	/* Create the remainder of the hash buffer, to generate the exchange hash */
	/* K_S, the host key */
	buf_put_pub_key(ses.kexhashbuf, ses.opts->hostkey, 
			ses.newkeys->algo_hostkey);
	/* e, exchange value sent by the client */
	buf_putmpint(ses.kexhashbuf, dh_e);
	/* f, exchange value sent by the server */
	buf_putmpint(ses.kexhashbuf, &dh_f);
	/* K, the shared secret */
	buf_putmpint(ses.kexhashbuf, ses.dh_K);

	/* calculate the hash H to sign */
	sha1_init(&hs);
	buf_setpos(ses.kexhashbuf, 0);
	sha1_process(&hs, buf_getptr(ses.kexhashbuf, ses.kexhashbuf->len),
			ses.kexhashbuf->len);
	sha1_done(&hs, ses.hash);
	buf_free(ses.kexhashbuf);
	ses.kexhashbuf = NULL;
	
	/* first time around, we set the session_id to H */
	if (ses.session_id == NULL) {
		/* create the session_id, this never needs freeing */
		ses.session_id = (unsigned char*)m_malloc(SHA1_HASH_SIZE);
		memcpy(ses.session_id, ses.hash, SHA1_HASH_SIZE);
	}
	
	/* we can start creating the kexdh_reply packet */
	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_KEXDH_REPLY);
	buf_put_pub_key(ses.writepayload, ses.opts->hostkey,
			ses.newkeys->algo_hostkey);

	/* put f */
	buf_putmpint(ses.writepayload, &dh_f);
	mp_clear(&dh_f);

	/* calc the signature */
	buf_put_sign(ses.writepayload, ses.opts->hostkey, 
			ses.newkeys->algo_hostkey, ses.hash, SHA1_HASH_SIZE);

	/* the SSH_MSG_KEXDH_REPLY is done */
	encrypt_packet();

	TRACE(("leave send_msg_kexdh_reply"));
}

/* read the client's choice of algorithms */
static void read_kex() {

	algo_type * algo;
	unsigned char* str;
	char * erralgo = NULL;

	buf_incrpos(ses.payload, 16); /* start after the cookie */

	ses.newkeys = (struct key_context*)m_malloc(sizeof(struct key_context));

	/* kex_algorithms */
	algo = buf_match_algo(ses.payload, sshkex);
	if (algo == NULL) {
		erralgo = "kex";
		goto error;
	}
	ses.newkeys->algo_kex = algo->val;

	/* server_host_key_algorithms */
	algo = buf_match_algo(ses.payload, sshhostkey);
	if (algo == NULL) {
		erralgo = "hostkey";
		goto error;
	}
	ses.newkeys->algo_hostkey = algo->val;

	/* encryption_algorithms_client_to_server */
	algo = buf_match_algo(ses.payload, sshciphers);
	if (algo == NULL) {
		erralgo = "enc c->s";
		goto error;
	}
	ses.newkeys->recv_algo_crypt = (struct dropbear_cipher*)algo->data;

	/* encryption_algorithms_server_to_client */
	algo = buf_match_algo(ses.payload, sshciphers);
	if (algo == NULL) {
		erralgo = "enc s->c";
		goto error;
	}
	ses.newkeys->trans_algo_crypt = (struct dropbear_cipher*)algo->data;

	/* mac_algorithms_client_to_server */
	algo = buf_match_algo(ses.payload, sshhashes);
	if (algo == NULL) {
		erralgo = "mac c->s";
		goto error;
	}
	ses.newkeys->recv_algo_mac = (struct dropbear_hash*)algo->data;

	/* mac_algorithms_server_to_client */
	algo = buf_match_algo(ses.payload, sshhashes);
	if (algo == NULL) {
		erralgo = "mac s->c";
		goto error;
	}
	ses.newkeys->trans_algo_mac = (struct dropbear_hash*)algo->data;

	/* compression_algorithms_client_to_server */
	algo = buf_match_algo(ses.payload, sshcompress);
	if (algo == NULL) {
		erralgo = "comp c->s";
		goto error;
	}
	ses.newkeys->recv_algo_comp = algo->val;

	/* compression_algorithms_server_to_client */
	algo = buf_match_algo(ses.payload, sshcompress);
	if (algo == NULL) {
		erralgo = "comp s->c";
		goto error;
	}
	ses.newkeys->trans_algo_comp = algo->val;

	/* languages_client_to_server */
	str = buf_getstring(ses.payload, NULL);
	m_free(str);

	/* languages_server_to_client */
	str = buf_getstring(ses.payload, NULL);
	m_free(str);

	/* first_kex_packet_follows */
	if (buf_getbyte(ses.payload)) {
		ses.kexstate.firstfollows = 1;
		/* XXX currently not handled */
	}

	/* reserved for future extensions */
	buf_getint(ses.payload);

	return;

error:
	dropbear_exit("no matching algo %s", erralgo);

}

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

	ses.kexstate.sentkexinit = 1;
}
