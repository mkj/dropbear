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


static void send_msg_kexdh_reply(mp_int *dh_e);

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
	ses.requirenext = SSH_MSG_NEWKEYS;
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
	
	m_mp_init_multi(&dh_g, &dh_p, &dh_q, &dh_y, &dh_f, NULL);

	/* read the prime and generator*/
	if (mp_read_unsigned_bin(&dh_p, (unsigned char*)dh_p_val, DH_P_LEN)
			!= MP_OKAY) {
		dropbear_exit("Diffie-Hellman error");
	}
	
	if (mp_set_int(&dh_g, DH_G_VAL) != MP_OKAY) {
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
void svr_read_kex() {

	algo_type * algo;
	char * erralgo = NULL;

	int goodguess = 0;
	int allgood = 1; /* we AND this with each goodguess and see if its still
						true after */

	buf_incrpos(ses.payload, 16); /* start after the cookie */

	ses.newkeys = (struct key_context*)m_malloc(sizeof(struct key_context));

	/* kex_algorithms */
	algo = svr_buf_match_algo(ses.payload, sshkex, &goodguess);
	allgood &= goodguess;
	if (algo == NULL) {
		erralgo = "kex";
		goto error;
	}
	ses.newkeys->algo_kex = algo->val;

	/* server_host_key_algorithms */
	algo = svr_buf_match_algo(ses.payload, sshhostkey, &goodguess);
	allgood &= goodguess;
	if (algo == NULL) {
		erralgo = "hostkey";
		goto error;
	}
	ses.newkeys->algo_hostkey = algo->val;

	/* encryption_algorithms_client_to_server */
	algo = svr_buf_match_algo(ses.payload, sshciphers, &goodguess);
	if (algo == NULL) {
		erralgo = "enc c->s";
		goto error;
	}
	ses.newkeys->recv_algo_crypt = (struct dropbear_cipher*)algo->data;

	/* encryption_algorithms_server_to_client */
	algo = svr_buf_match_algo(ses.payload, sshciphers, &goodguess);
	if (algo == NULL) {
		erralgo = "enc s->c";
		goto error;
	}
	ses.newkeys->trans_algo_crypt = (struct dropbear_cipher*)algo->data;

	/* mac_algorithms_client_to_server */
	algo = svr_buf_match_algo(ses.payload, sshhashes, &goodguess);
	if (algo == NULL) {
		erralgo = "mac c->s";
		goto error;
	}
	ses.newkeys->recv_algo_mac = (struct dropbear_hash*)algo->data;

	/* mac_algorithms_server_to_client */
	algo = svr_buf_match_algo(ses.payload, sshhashes, &goodguess);
	if (algo == NULL) {
		erralgo = "mac s->c";
		goto error;
	}
	ses.newkeys->trans_algo_mac = (struct dropbear_hash*)algo->data;

	/* compression_algorithms_client_to_server */
	algo = svr_buf_match_algo(ses.payload, sshcompress, &goodguess);
	if (algo == NULL) {
		erralgo = "comp c->s";
		goto error;
	}
	ses.newkeys->recv_algo_comp = algo->val;

	/* compression_algorithms_server_to_client */
	algo = svr_buf_match_algo(ses.payload, sshcompress, &goodguess);
	if (algo == NULL) {
		erralgo = "comp s->c";
		goto error;
	}
	ses.newkeys->trans_algo_comp = algo->val;

	/* languages_client_to_server */
	buf_eatstring(ses.payload);

	/* languages_server_to_client */
	buf_eatstring(ses.payload);

	/* first_kex_packet_follows */
	if (buf_getbyte(ses.payload)) {
		ses.kexstate.firstfollows = 1;
		/* if the guess wasn't good, we ignore the packet sent */
		if (!allgood) {
			ses.ignorenext = 1;
		}
	}

	/* reserved for future extensions */
	buf_getint(ses.payload);
	return;

error:
	dropbear_exit("no matching algo %s", erralgo);
}
