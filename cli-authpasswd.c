/*
 * Dropbear SSH
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
#include "buffer.h"
#include "dbutil.h"
#include "session.h"
#include "ssh.h"
#include "runopts.h"

#ifdef ENABLE_CLI_PASSWORD_AUTH
int cli_auth_password() {

	char* password = NULL;
	TRACE(("enter cli_auth_password"))

	CHECKCLEARTOWRITE();
	password = getpass("Password: ");

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_REQUEST);

	buf_putstring(ses.writepayload, cli_opts.username,
			strlen(cli_opts.username));

	buf_putstring(ses.writepayload, SSH_SERVICE_CONNECTION, 
			SSH_SERVICE_CONNECTION_LEN);

	buf_putstring(ses.writepayload, AUTH_METHOD_PASSWORD, 
			AUTH_METHOD_PASSWORD_LEN);

	buf_putbyte(ses.writepayload, 0); /* FALSE - so says the spec */

	buf_putstring(ses.writepayload, password, strlen(password));

	encrypt_packet();
	m_burn(password, strlen(password));

	TRACE(("leave cli_auth_password"))
	return 1; /* Password auth can always be tried */

}
#endif
