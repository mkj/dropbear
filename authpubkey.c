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
 * furnished to do so, subject to the following condition:
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

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "options.h"
#include "session.h"
#include "util.h"
#include "buffer.h"
#include "signkey.h"
#include "auth.h"
#include "authpubkey.h"
#include "ssh.h"
#include "packet.h"
#include "algo.h"

#ifdef DROPBEAR_PUBKEY_AUTH

#define MIN_AUTHKEYS_LINE 10 /* "ssh-rsa AB" - short but doesn't matter */
#define MAX_AUTHKEYS_LINE 1000 /* max length of a line in authkeys */
#define MIN_AUTHKEYS_FILE MIN_AUTHKEYS_LINE
#define MAX_AUTHKEYS_FILE 10000 /* should allow at least 20 authkeys */

static int checkpubkey(unsigned char* algo, unsigned int algolen,
		unsigned char* keyblob, unsigned int keybloblen);
static int checkpubkeyperms();
static void send_msg_userauth_pk_ok(unsigned char* algo, unsigned int algolen,
		unsigned char* keyblob, unsigned int keybloblen);
static int checkfileperm(char * filename);
static int getauthline(buffer * line, FILE * authfile);

/* process a pubkey auth request */
void pubkeyauth() {

	unsigned char testkey; /* whether we're just checking if a key is usable */
	unsigned char* algo = NULL; /* pubkey algo */
	unsigned int algolen;
	unsigned char* keyblob;
	unsigned int keybloblen;
	buffer * signbuf = NULL;
	unsigned int sigoffset;
	sign_key * key = NULL;

	TRACE(("enter pubkeyauth"));

	/* 0 indicates we just want to check if key can be used, 1 is an
	 * actual attempt*/
	testkey = (buf_getbyte(ses.payload) == 0);

	algo = buf_getstring(ses.payload, &algolen);
	keybloblen = buf_getint(ses.payload);
	keyblob = buf_getptr(ses.payload, keybloblen);

	/* check if the key is valid */
	if (!checkpubkey(algo, algolen, keyblob, keybloblen)) {
		send_msg_userauth_failure(0, 0);
		goto out;
	}

	/* let them know that the key is ok to use */
	if (testkey) {
		send_msg_userauth_pk_ok(algo, algolen, keyblob, keybloblen);
		goto out;
	}

	/* now we can actually verify the signature */
	
	/* get the key */
	key = new_sign_key();
	if (buf_get_pub_key(ses.payload, key, DROPBEAR_SIGNKEY_ANY) != 0) {
		send_msg_userauth_failure(0, 1);
		goto out;
	}

	/* create the data which has been signed - this a string containing
	 * session_id, concatenated with the payload packet up to the signature */
	signbuf = buf_new(ses.payload->pos + 4 + SHA1_HASH_SIZE);
	buf_putstring(signbuf, ses.session_id, SHA1_HASH_SIZE);
	sigoffset = ses.payload->pos;
	buf_setpos(ses.payload, 0);
	memcpy(buf_getwriteptr(signbuf, sigoffset),
			buf_getptr(ses.payload, sigoffset), sigoffset);
	buf_incrwritepos(signbuf, sigoffset);
	buf_setpos(ses.payload, sigoffset);

	buf_setpos(signbuf, 0);
	/* ... and finally verify the signature */
	if (buf_verify(ses.payload, key, buf_getptr(signbuf, signbuf->len),
				signbuf->len) == 1) {
		send_msg_userauth_success();
		assert(ses.authstate.username);
		dropbear_log(LOG_AUTHPRIV | LOG_INFO,
				"pubkey auth succeeded for '%s'", ses.authstate.username);
	} else {
		send_msg_userauth_failure(0, 1);
	}

out:
	if (signbuf) {
		buf_free(signbuf);
	}
	if (algo) {
		m_free(algo);
	}
	if (key) {
		sign_key_free(key);

	}
	TRACE(("leave pubkeyauth"));
}

/* Reply that the key is valid for auth */
static void send_msg_userauth_pk_ok(unsigned char* algo, unsigned int algolen,
		unsigned char* keyblob, unsigned int keybloblen) {

	TRACE(("enter send_msg_userauth_pk_ok"));
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_PK_OK);
	buf_putstring(ses.writepayload, algo, algolen);
	buf_putstring(ses.writepayload, keyblob, keybloblen);

	encrypt_packet();
	TRACE(("leave send_msg_userauth_pk_ok"));

}

/* Returns 1 if key is ok for auth, 0 otherwise */
static int checkpubkey(unsigned char* algo, unsigned int algolen,
		unsigned char* keyblob, unsigned int keybloblen) {

	FILE * authfile = NULL;
	char * filename = NULL;
	int ret = 0;
	buffer * line = NULL;
	buffer * decodekey = NULL;
	unsigned long decodekeylen;
	unsigned char* filealgo = NULL;
	unsigned int filealgolen;
	int len;
	
	TRACE(("enter checkpubkey"));

	/* check that we can use the algo */
	if (have_algo(algo, algolen, sshhostkey) != 0) {
		goto out;
	}

	/* check file permissions */
	if (!checkpubkeyperms()) {
		TRACE(("perms failed"));
		goto out;
	}

	/* we don't need to check pw and pw_dir for validity, since
	 * its been done in checkpubkeyperms. */
	len = strlen(ses.authstate.pw->pw_dir);
	filename = m_malloc(len + 30);
	strncpy(filename, ses.authstate.pw->pw_dir, len+1);
	strncat(filename, "/.ssh/authorized_keys", 21);

	/* open the file */
	authfile = fopen(filename, "r");
	if (authfile == NULL) {
		goto out;
	}

	line = buf_new(MAX_AUTHKEYS_LINE);

	/* iterate through the lines */
	do {
		/* free reused vars */
		if (decodekey) {
			buf_free(decodekey);
			decodekey = NULL;
		}
		m_free(filealgo);

		if (!getauthline(line, authfile)) {
			/* EOF reached */
			break;
		}

		if (line->len < MIN_AUTHKEYS_LINE) {
			continue;
		}

		/* check the key type */
		if (strncmp(buf_getptr(line, algolen), algo, algolen) != 0) {
			continue;
		}
		buf_incrpos(line, algolen);
		
		/* check for space (' ') character */
		if (buf_getbyte(line) != ' ') {
			continue;
		}

		/* now we have the actual data */
		decodekeylen = (line->len - line->pos) * 2;
		decodekey = buf_new(decodekeylen);
		if (base64_decode(buf_getptr(line, line->len - line->pos),
					line->len - line->pos,
					buf_getwriteptr(decodekey, decodekey->size),
					&decodekeylen) != CRYPT_OK) {
			continue;
		}
		buf_incrlen(decodekey, decodekeylen);
		
		/* compare the keys */
		if (decodekeylen != keybloblen || memcmp(
					buf_getptr(decodekey, decodekey->len),
					keyblob, decodekey->len) != 0) {
			continue;
		}

		/* and also check that the algo specified and the algo in the key
		 * itself match */
		filealgo = buf_getstring(decodekey, &filealgolen);
		if (filealgolen != algolen || memcmp(filealgo, algo, algolen) != 0) {
			continue;
		}

		/* now we know this key is good */
		ret = 1;
		break;
		
	} while (1);

out:
	if (authfile) {
		fclose(authfile);
	}
	if (line) {
		buf_free(line);
	}
	if (decodekey) {
		buf_free(decodekey);
	}
	m_free(filename);
	m_free(filealgo);
	TRACE(("leave checkpubkey"));
	return ret;
}

/* get a line from the file into buffer in the style expected for an
 * authkeys file, we stop after reaching a '=', but will read out to the
 * end of the file.
 * Will return 1 if data is read, or 0 on EOF. Note that it may return 1
 * even with an empty line */
static int getauthline(buffer * line, FILE * authfile) {

	int endofbase64 = 0;
	int c;
	int count = 0;
	buf_setpos(line, 0);
	buf_setlen(line, 0);
	for (;;) {
		c = getc(authfile);
		if (c == EOF || c == '\n' || c == '\r') {
			buf_setpos(line, 0);
			/* return 0 on EOF */
			return !(count == 0 && c == EOF);
		}
		if (c == '=') { /* base64 end char */
			endofbase64 = 1;
		}
		if ((!endofbase64 || c == '=') && line->pos < line->size) {
			buf_putbyte(line, (unsigned char)c);
		} /* otherwise loop until EOL, ignoring extra */
		count++;
	}
}	

/* Returns 1 if file permissions for pubkeys are ok, 0 otherwise */
/* Checks that the user's homedir, ~/.ssh, and ~/.ssh/authorized_keys
 * are all owned by either root or the user, and are g-w, o-w */
static int checkpubkeyperms() {

	char* filename = NULL; 
	int ret = 0;
	unsigned int len;

	TRACE(("enter checkpubkeyperms"));

	assert(ses.authstate.pw);
	if (ses.authstate.pw->pw_dir == NULL) {
		goto out;
	}

	if ((len = strlen(ses.authstate.pw->pw_dir)) == 0) {
		goto out;
	}

	/* allocate max required pathname storage,
	 * = path + "/.ssh/authorized_keys" + '\0' = pathlen + 22 */
	filename = m_malloc(len + 30);
	strncpy(filename, ses.authstate.pw->pw_dir, len+1);

	/* check ~ */
	if (!checkfileperm(filename)) {
		goto out;
	}

	/* check ~/.ssh */
	strncat(filename, "/.ssh", 5); /* strlen("/.ssh") == 5 */
	if (!checkfileperm(filename)) {
		goto out;
	}

	/* now check ~/.ssh/authorized_keys */
	strncat(filename, "/authorized_keys", 16);
	if (!checkfileperm(filename)) {
		goto out;
	}

	/* file looks ok, return 1 */
	ret = 1;
	
out:
	m_free(filename);

	TRACE(("leave checkpubkeyperms"));
	return ret;
}

/* returns 1 on valid, 0 on invalid perms */
static int checkfileperm(char * filename) {
	struct stat filestat;

	if (stat(filename, &filestat) != 0) {
		return 0;
	}
	/* check ownership - user or root only*/
	if (filestat.st_uid != ses.authstate.pw->pw_uid
			&& filestat.st_uid != 0) {
		return 0;
	}
	/* check permissions - don't want group or others +w */
	if (filestat.st_mode & (S_IWGRP | S_IWOTH)) {
		return 0;
	}
	return 1;
}


#endif /* DROPBEAR_PUBKEY_AUTH */
