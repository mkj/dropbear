#include "includes.h"
#include "buffer.h"
#include "dbutil.h"
#include "session.h"
#include "ssh.h"

int cli_auth_password() {

	char* password = NULL;
	TRACE(("enter cli_auth_password"));

	CHECKCLEARTOWRITE();
	password = getpass("Password: ");

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_REQUEST);

	buf_putstring(ses.writepayload, ses.authstate.username,
			strlen(ses.authstate.username));

	buf_putstring(ses.writepayload, SSH_SERVICE_CONNECTION, 
			SSH_SERVICE_CONNECTION_LEN);

	buf_putstring(ses.writepayload, AUTH_METHOD_PASSWORD, 
			AUTH_METHOD_PASSWORD_LEN);

	buf_putbyte(ses.writepayload, 0); /* FALSE - so says the spec */

	buf_putstring(ses.writepayload, password, strlen(password));

	encrypt_packet();
	m_burn(password, strlen(password));

	TRACE(("leave cli_auth_password"));
	return 1; /* Password auth can always be tried */

}
