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

#include <unistd.h>

#include "options.h"
#include "session.h"
#include "buffer.h"
#include "util.h"
#include "auth.h"
#include "authpasswd.h"

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif

#ifdef DROPBEAR_PASSWORD_AUTH

/* process a password auth request */
void passwordauth() {
	
#ifdef HAVE_SHADOW_H
	struct spwd *spasswd;
#endif
	char * usercrypt;
	unsigned char * password;
	unsigned int passwordlen;
	char * cryptpw;
	unsigned char changepw;

	usercrypt = ses.authstate.pw->pw_passwd;
#ifdef HAVE_SHADOW_H
	/* get the shadow password if possible */
	spasswd = getspnam(ses.authstate.pw->pw_name);
	if (spasswd != NULL && spasswd->sp_pwdp != NULL) {
		usercrypt = spasswd->sp_pwdp;
	}
#endif

#ifdef HACKCRYPT
	/* debugging crypt for non-root testing with shadows */
	usercrypt = HACKCRYPT;
#endif

	/* check for empty password */
	if (usercrypt[0] == '\0') {
		send_msg_userauth_failure(0, 1);
		return;
	}

	/* check if client wants to change password */
	changepw = buf_getbyte(ses.payload);
	if (changepw) {
		/* not implemented by this server */
		send_msg_userauth_failure(0, 1);
		return;
	}

	password = buf_getstring(ses.payload, &passwordlen);

	/* clear the buffer containing the password */
	buf_incrpos(ses.payload, -passwordlen - 4);
	m_burn(buf_getptr(ses.payload, passwordlen + 4), passwordlen + 4);

	cryptpw = crypt((char*)password, usercrypt);

	if (strcmp(cryptpw, usercrypt) == 0) {
		/* successful authentication */
		send_msg_userauth_success();
		assert(ses.authstate.username);
		dropbear_log(LOG_AUTHPRIV | LOG_INFO, 
				"password auth succeeded for '%s'",
				ses.authstate.username);
	} else {
		send_msg_userauth_failure(0, 1);
	}

	m_burn(password, passwordlen);
	m_free(password);
}

#endif /* DROPBEAR_PASSWORD_AUTH */
