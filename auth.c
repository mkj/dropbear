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

/* This file (auth.c) handles authentication requests, passing it to the
 * particular type (auth-passwd, auth-pubkey). */

#include "includes.h"
#include "util.h"
#include "session.h"
#include "buffer.h"
#include "ssh.h"
#include "packet.h"
#include "auth.h"
#include "authpasswd.h"
#include "authpubkey.h"

static void authclear();
static int checkusername(unsigned char *username, unsigned int userlen);
static void send_msg_userauth_banner();

/* initialise the first time for a session, resetting all parameters */
void authinitialise() {

	ses.authstate.failcount = 0;
	authclear();
	
}

/* Reset the auth state, but don't reset the failcount. This is for if the
 * user decides to try with a different username etc, and is also invoked
 * on initialisation */
static void authclear() {
	
	ses.authstate.authdone = 0;
	ses.authstate.pw = NULL;
	ses.authstate.username = NULL;
	ses.authstate.printableuser = NULL;
	ses.authstate.authtypes = 0;
#ifdef DROPBEAR_PUBKEY_AUTH
	ses.authstate.authtypes |= AUTH_TYPE_PUBKEY;
#endif
#ifdef DROPBEAR_PASSWORD_AUTH
	ses.authstate.authtypes |= AUTH_TYPE_PASSWORD;
#endif

}

/* Send a banner message if specified to the client. The client might
 * ignore this, but possibly serves as a legal "no trespassing" sign */
static void send_msg_userauth_banner() {

	TRACE(("enter send_msg_userauth_banner"));
	if (ses.opts->banner == NULL) {
		TRACE(("leave send_msg_userauth_banner: banner is NULL"));
		return;
	}

	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_BANNER);
	buf_putstring(ses.writepayload, buf_getptr(ses.opts->banner,
				ses.opts->banner->len), ses.opts->banner->len);
	buf_putstring(ses.writepayload, "en", 2);

	encrypt_packet();
	buf_free(ses.opts->banner);
	ses.opts->banner = NULL;

	TRACE(("leave send_msg_userauth_banner"));
}

/* handle a userauth request, check validity, pass to password or pubkey
 * checking, and handle success or failure */
void recv_msg_userauth_request() {

	unsigned char *username, *servicename, *methodname;
	unsigned int userlen, servicelen, methodlen;

	TRACE(("enter recv_msg_userauth_request"));

	/* ignore packets if auth is already done */
	if (ses.authstate.authdone == 1) {
		return;
	}

	/* send the banner if it exists, it will only exist once */
	if (ses.opts->banner) {
		send_msg_userauth_banner();
	}

	
	username = buf_getstring(ses.payload, &userlen);
	servicename = buf_getstring(ses.payload, &servicelen);
	methodname = buf_getstring(ses.payload, &methodlen);

	/* only handle 'ssh-connection' currently */
	if (servicelen != SSH_SERVICE_CONNECTION_LEN
			&& (strncmp(servicename, SSH_SERVICE_CONNECTION,
					SSH_SERVICE_CONNECTION_LEN) != 0)) {
		
		/* TODO - disconnect here */
		m_free(username);
		m_free(servicename);
		m_free(methodname);
		dropbear_exit("unknown service in auth");
	}

	/* user wants to know what methods are supported */
	if (methodlen == AUTH_METHOD_NONE_LEN &&
			strncmp(methodname, AUTH_METHOD_NONE,
				AUTH_METHOD_NONE_LEN) == 0) {
		send_msg_userauth_failure(0, 0);
		goto out;
	}
	
	/* check username is good before continuing */
	if (checkusername(username, userlen) == DROPBEAR_FAILURE) {
		/* username is invalid/no shell/etc - send failure */
		TRACE(("sending checkusername failure"));
		send_msg_userauth_failure(0, 1);
		goto out;
	}

#ifdef DROPBEAR_PASSWORD_AUTH
	/* user wants to try password auth */
	if (methodlen == AUTH_METHOD_PASSWORD_LEN &&
			strncmp(methodname, AUTH_METHOD_PASSWORD,
				AUTH_METHOD_PASSWORD_LEN) == 0) {
		passwordauth(username, userlen);
		goto out;
	}
#endif

#ifdef DROPBEAR_PUBKEY_AUTH
	/* user wants to try pubkey auth */
	if (methodlen == AUTH_METHOD_PUBKEY_LEN &&
			strncmp(methodname, AUTH_METHOD_PUBKEY,
				AUTH_METHOD_PUBKEY_LEN) == 0) {
		pubkeyauth(username, userlen);
		goto out;
	}
#endif

	/* nothing matched, we just fail */
	send_msg_userauth_failure(0, 1);

out:

	m_free(username);
	m_free(servicename);
	m_free(methodname);
}

/* Check that the username exists, has a non-empty password, and has a valid
 * shell.
 * returns DROPBEAR_SUCCESS on valid username, DROPBEAR_FAILURE on failure */
static int checkusername(unsigned char *username, unsigned int userlen) {

	char* shell;
	char* newprintableuser;
	
	TRACE(("enter checkusername"));
	if (userlen > MAX_USERNAME_LEN) {
		return DROPBEAR_FAILURE;
	}

	newprintableuser = stripcontrol(username);

	/* new user or username has changed */
	if (ses.authstate.username == NULL ||
		strcmp(username, ses.authstate.username) != 0) {
			/* the username needs resetting */
			if (ses.authstate.username != NULL) {
				dropbear_log(LOG_WARNING,
					"client trying multiple usernames: '%s' and '%s' from %s",
					ses.authstate.printableuser, newprintableuser,
					ses.addrstring);
				m_free(ses.authstate.username);
				m_free(ses.authstate.printableuser);
			}
			authclear();
			ses.authstate.pw = getpwnam((char*)username);
			ses.authstate.username = strdup(username);
			ses.authstate.printableuser = newprintableuser;
	}

	/* check that user exists */
	if (ses.authstate.pw == NULL) {
		TRACE(("leave checkusername: user doesn't exist"));
		dropbear_log(LOG_WARNING,
				"login attempt for nonexistant user '%s' from %s",
				username, ses.addrstring);
		send_msg_userauth_failure(0, 1);
		return DROPBEAR_FAILURE;
	}

	/* check for an empty password */
	if (ses.authstate.pw->pw_passwd[0] == '\0') {
		TRACE(("leave checkusername: empty pword"));
		dropbear_log(LOG_WARNING,
				"disallowing login for '%s' from %s - empty password",
				username, ses.addrstring);
		send_msg_userauth_failure(0, 1);
		return DROPBEAR_FAILURE;
	}

	TRACE(("shell is %s", ses.authstate.pw->pw_shell));
	/* check that the shell is valid */
	/* XXX - todo check this is correct: empty shell is ok */
	if (ses.authstate.pw->pw_shell[0] == '\0') {
		goto goodshell;
	}
	setusershell();
	while ((shell = getusershell()) != NULL) {
		TRACE(("test shell is '%s'", shell));
		if (strcmp(shell, ses.authstate.pw->pw_shell) == 0) {
			/* have a match */
			goto goodshell;
		}
	}
	/* no matching shell */
	endusershell();
	TRACE(("no matching shell"));
	dropbear_log(LOG_WARNING,
			"disallowing login for '%s' from %s - invalid shell",
			username, ses.addrstring);
	send_msg_userauth_failure(0, 1);
	return DROPBEAR_FAILURE;
	
goodshell:
	endusershell();
	TRACE(("matching shell"));

	TRACE(("uid = %d\n", ses.authstate.pw->pw_uid));
	TRACE(("leave checkusername"));
	return DROPBEAR_SUCCESS;

}

/* Send a failure message to the client, in responds to a userauth_request.
 * Partial indicates whether to set the "partial success" flag,
 * incrfail is whether to count this failure in the failure count (which
 * is limited. This function also handles disconnection after too many
 * failures */
void send_msg_userauth_failure(int partial, int incrfail) {

	buffer *typebuf;

	TRACE(("enter send_msg_userauth_failure"));

	CHECKCLEARTOWRITE();
	
	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_FAILURE);

	/* put a list of allowed types */
	typebuf = buf_new(30); /* long enough for PUBKEY and PASSWORD */

	if (ses.authstate.authtypes & AUTH_TYPE_PUBKEY) {
		buf_putbytes(typebuf, AUTH_METHOD_PUBKEY, AUTH_METHOD_PUBKEY_LEN);
		if (ses.authstate.authtypes & AUTH_TYPE_PASSWORD) {
			buf_putbyte(typebuf, ',');
		}
	}
	
	if (ses.authstate.authtypes & AUTH_TYPE_PASSWORD) {
		buf_putbytes(typebuf, AUTH_METHOD_PASSWORD, AUTH_METHOD_PASSWORD_LEN);
	}

	buf_setpos(typebuf, 0);
	buf_putstring(ses.writepayload, buf_getptr(typebuf, typebuf->len),
			typebuf->len);
	buf_free(typebuf);

	buf_putbyte(ses.writepayload, partial ? 1 : 0);
	encrypt_packet();

	if (incrfail) {
		usleep(100000); /* XXX improve this */
		ses.authstate.failcount++;
	}

	if (ses.authstate.failcount >= MAX_AUTH_TRIES) {
		char * userstr;
		/* XXX - send disconnect ? */
		TRACE(("Max auth tries reached, exiting"));

		if (ses.authstate.username == NULL) {
			userstr = "is unknown!!!!";
		} else {
			userstr = ses.authstate.printableuser;
		}
		dropbear_exit("Max auth tries reached - user %s", userstr);
	}
	
	TRACE(("leave send_msg_userauth_failure"));
}

/* Send a success message to the user, and set the "authdone" flag */
void send_msg_userauth_success() {

	TRACE(("enter send_msg_userauth_success"));

	CHECKCLEARTOWRITE();

	assert(ses.authstate.username);

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_SUCCESS);
	encrypt_packet();

	ses.authstate.authdone = 1;
	close(ses.childpipe); /* remove from the list of pre-auth sockets */
	TRACE(("leave send_msg_userauth_success"));

}
