#include "includes.h"
#include "session.h"
#include "auth.h"
#include "dbutil.h"
#include "buffer.h"
#include "ssh.h"
#include "packet.h"
#include "runopts.h"

void cli_authinitialise() {

	memset(&ses.authstate, 0, sizeof(ses.authstate));
}


void cli_get_user() {

	uid_t uid;
	struct passwd *pw; 

	TRACE(("enter cli_get_user"));
	if (cli_opts.username != NULL) {
		ses.authstate.username = cli_opts.username;
	} else {
		uid = getuid();
		
		pw = getpwuid(uid);
		if (pw == NULL || pw->pw_name == NULL) {
			dropbear_exit("Couldn't find username for current user");
		}

		ses.authstate.username = m_strdup(pw->pw_name);
	}
	TRACE(("leave cli_get_user: %s", cli_ses.username));
}

/* Send a "none" auth request to get available methods */
void cli_auth_getmethods() {

	TRACE(("enter cli_auth_getmethods"));

	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_REQUEST);
	buf_putstring(ses.writepayload, ses.authstate.username,
			strlen(ses.authstate.username));
	buf_putstring(ses.writepayload, SSH_SERVICE_CONNECTION, 
			SSH_SERVICE_CONNECTION_LEN);
	buf_putstring(ses.writepayload, "none", 4); /* 'none' method */

	encrypt_packet();
	cli_ses.state = USERAUTH_METHODS_SENT;
	TRACE(("leave cli_auth_getmethods"));

}

void recv_msg_userauth_failure() {

	unsigned char * methods = NULL;
	unsigned char * tok = NULL;
	unsigned int methlen = 0;
	unsigned int partial = 0;
	unsigned int i = 0;

	TRACE(("<- MSG_USERAUTH_FAILURE"));
	TRACE(("enter recv_msg_userauth_failure"));

	methods = buf_getstring(ses.payload, &methlen);

	partial = buf_getbyte(ses.payload);

	if (partial) {
		dropbear_log(LOG_INFO, "Authentication partially succeeded, more attempts required");
	} else {
		ses.authstate.failcount++;
	}

	TRACE(("Methods (len %d): '%s'", methlen, methods));

	ses.authstate.authdone=0;
	ses.authstate.authtypes=0;

	/* Split with nulls rather than commas */
	for (i = 0; i < methlen; i++) {
		if (methods[i] == ',') {
			methods[i] = '\0';
		}
	}

	tok = methods; /* tok stores the next method we'll compare */
	for (i = 0; i <= methlen; i++) {
		if (methods[i] == '\0') {
			TRACE(("auth method '%s'\n", tok));
#ifdef DROPBEAR_PUBKEY_AUTH
			if (strncmp(AUTH_METHOD_PUBKEY, tok,
				AUTH_METHOD_PUBKEY_LEN) == 0) {
				ses.authstate.authtypes |= AUTH_TYPE_PUBKEY;
			}
#endif
#ifdef DROPBEAR_PASSWORD_AUTH
			if (strncmp(AUTH_METHOD_PASSWORD, tok,
				AUTH_METHOD_PASSWORD_LEN) == 0) {
				ses.authstate.authtypes |= AUTH_TYPE_PASSWORD;
			}
#endif
			tok = &methods[i]; /* Must make sure we don't use it after
								  the last loop, since it'll point
								  to something undefined */
		}
	}

	cli_ses.state = USERAUTH_FAIL_RCVD;
		
	TRACE(("leave recv_msg_userauth_failure"));
}

void recv_msg_userauth_success() {
	TRACE(("received msg_userauth_success"));
	ses.authstate.authdone = 1;
}

void cli_auth_try() {

	TRACE(("enter cli_auth_try"));
	int finished = 0;

	CHECKCLEARTOWRITE();
	
	/* XXX We hardcode that we try a pubkey first */
#ifdef DROPBEAR_PUBKEY_AUTH
	if (ses.authstate.authtypes & AUTH_TYPE_PUBKEY) {
		finished = cli_auth_pubkey();
	}
#endif

#ifdef DROPBEAR_PASSWORD_AUTH
	if (!finished && ses.authstate.authtypes & AUTH_TYPE_PASSWORD) {
		finished = cli_auth_password();
	}
#endif

	if (!finished) {
		dropbear_exit("No auth methods could be used.");
	}

	cli_ses.state = USERAUTH_REQ_SENT;
	TRACE(("leave cli_auth_try"));
}
