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
#include "session.h"
#include "dbutil.h"
#include "algo.h"
#include "buffer.h"
#include "session.h"
#include "kex.h"
#include "ssh.h"
#include "packet.h"
#include "bignum.h"
#include "random.h"
#include "runopts.h"
#include "signkey.h"



void send_msg_kexdh_init() {

	cli_ses.dh_e = (mp_int*)m_malloc(sizeof(mp_int));
	cli_ses.dh_x = (mp_int*)m_malloc(sizeof(mp_int));

	m_mp_init_multi(cli_ses.dh_e, cli_ses.dh_x);
	gen_kexdh_vals(cli_ses.dh_e, cli_ses.dh_x);

	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_KEXDH_INIT);
	buf_putmpint(ses.writepayload, cli_ses.dh_e);
	encrypt_packet();
	ses.requirenext = SSH_MSG_KEXDH_REPLY;
}

/* Handle a diffie-hellman key exchange reply. */
void recv_msg_kexdh_reply() {

	mp_int dh_f;
	sign_key *hostkey = NULL;
	int type;

	type = ses.newkeys->algo_hostkey;

	hostkey = new_sign_key();
	if (buf_get_pub_key(ses.payload, hostkey, &type) != DROPBEAR_SUCCESS) {
		dropbear_exit("Bad KEX packet");
	}

	m_mp_init(&dh_f);
	if (buf_getmpint(ses.payload, &dh_f) != DROPBEAR_SUCCESS) {
		dropbear_exit("Bad KEX packet");
	}

	kexdh_comb_key(cli_ses.dh_e, cli_ses.dh_x, &dh_f, hostkey);
	mp_clear(&dh_f);

	if (buf_verify(ses.payload, hostkey, ses.hash, SHA1_HASH_SIZE) 
			!= DROPBEAR_SUCCESS) {
		dropbear_exit("Bad hostkey signature");
	}

	/* XXX TODO */
	dropbear_log(LOG_WARNING,"Not checking hostkey fingerprint for the moment");

	sign_key_free(hostkey);
	hostkey = NULL;

	send_msg_newkeys();
	ses.requirenext = SSH_MSG_NEWKEYS;
	TRACE(("leave recv_msg_kexdh_init"));
}
