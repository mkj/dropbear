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

/* Validates a user password */

#include "includes.h"
#include "session.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"

#if defined(HAVE_SECURITY_PAM_APPL_H)
#include <security/pam_appl.h>
#elif defined (HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif

struct UserDataS {
	char* user;
	char* passwd;
};

/* PAM conversation function - for now we only handle one message */
int 
pamConvFunc(int num_msg, 
		const struct pam_message **msg,
		struct pam_response **respp, 
		void *appdata_ptr) {

	int rc = PAM_SUCCESS;
	struct pam_response* resp = NULL;
	struct UserDataS* userDatap = (struct UserDataS*) appdata_ptr;
	const char* message = (*msg)->msg;

	TRACE(("enter pamConvFunc"));
	TRACE(("msg_style is %d", (*msg)->msg_style));
	if (message) {
		TRACE(("message is '%s'", message));
	} else {
		TRACE(("null message"));
	}

	switch((*msg)->msg_style) {

		case PAM_PROMPT_ECHO_OFF:

			if (strcmp(message, "Password:") != 0) {
					TRACE(("PAM_PROMPT_ECHO_OFF: unrecognized prompt"));
					rc = PAM_CONV_ERR;
					break;
			}

			/* XXX leak */
			resp = (struct pam_response*) m_malloc(sizeof(struct pam_response));
			/* XXX leak */
			resp->resp = (char*) m_strdup(userDatap->passwd);
			resp->resp_retcode = 0;
			(*respp) = resp;
			break;


		case PAM_PROMPT_ECHO_ON:

			if ((strcmp(message, "login: " ) != 0) 
					&& (strcmp(message, "login:" ) != 0)
					&& (strcmp(message, "Please enter username: " ) != 0)) {
				TRACE(("PAM_PROMPT_ECHO_ON: unrecognized prompt"));
				rc = PAM_CONV_ERR;
				break;
			}

			/* XXX leak */
			resp = (struct pam_response*) m_malloc(sizeof(struct pam_response));
			/* XXX leak */
			resp->resp = (char*) m_strdup(userDatap->user);
			TRACE(("userDatap->user='%s'", userDatap->user));

			resp->resp_retcode = 0;
			(*respp) = resp;
			break;

		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
		case PAM_RADIO_TYPE:
		case PAM_BINARY_PROMPT:
			TRACE(("Unhandled message type"));
			rc = PAM_CONV_ERR;
			break;

		default:
			TRACE(("Unknown message type"));
			rc = PAM_CONV_ERR;
			break;      
	}

	TRACE(("leave pamConvFunc, rc %d", rc));

	return rc;
}

/* Process a password auth request, sending success or failure messages as
 * appropriate. To the client it looks like it's doing normal password auth (as opposed to keyboard-interactive or something), so the pam module has to be fairly standard (ie just "what's your username, what's your password, OK").
 *
 * Keyboard interactive would be a lot nicer, but since PAM is synchronous, it
 * gets very messy trying to send the interactive challenges, and read the
 * interactive responses, over the network. */
void svr_auth_pam() {

	struct UserDataS userData;
	struct pam_conv pamConv = {
		pamConvFunc,
		&userData /* submitted to pamvConvFunc as appdata_ptr */ 
	};

	pam_handle_t* pamHandlep = NULL;

	unsigned char * password = NULL;
	unsigned int passwordlen;

	int rc = PAM_SUCCESS;
	unsigned char changepw;

	/* check if client wants to change password */
	changepw = buf_getbyte(ses.payload);
	if (changepw) {
		/* not implemented by this server */
		send_msg_userauth_failure(0, 1);
		goto cleanup;
	}

	password = buf_getstring(ses.payload, &passwordlen);

	/* used to pass data to the PAM conversation function */
	userData.user = ses.authstate.printableuser;
	userData.passwd = password;

	/* Init pam */
	if ((rc = pam_start("sshd", NULL, &pamConv, &pamHandlep)) != PAM_SUCCESS) {
		dropbear_log(LOG_WARNING, "pam_start() failed, rc=%d, %s\n", 
				rc, pam_strerror(pamHandlep, rc));
		goto cleanup;
	}

	/* just to set it to something */
	if ((rc = pam_set_item(pamHandlep, PAM_TTY, "ssh") != PAM_SUCCESS)) {
		dropbear_log(LOG_WARNING, "pam_set_item() failed, rc=%d, %s\n", 
				rc, pam_strerror(pamHandlep, rc));
		goto cleanup;
	}

	(void) pam_fail_delay(pamHandlep, 0 /* musec_delay */);

	/* (void) pam_set_item(pamHandlep, PAM_FAIL_DELAY, (void*) pamDelayFunc); */

	if ((rc = pam_authenticate(pamHandlep, 0)) != PAM_SUCCESS) {
		dropbear_log(LOG_WARNING, "pam_authenticate() failed, rc=%d, %s\n", 
				rc, pam_strerror(pamHandlep, rc));
		dropbear_log(LOG_WARNING,
				"bad pam password attempt for '%s'",
				ses.authstate.printableuser);
		send_msg_userauth_failure(0, 1);
		goto cleanup;
	}

	if ((rc = pam_acct_mgmt(pamHandlep, 0)) != PAM_SUCCESS) {
		dropbear_log(LOG_WARNING, "pam_acct_mgmt() failed, rc=%d, %s\n", 
				rc, pam_strerror(pamHandlep, rc));
		dropbear_log(LOG_WARNING,
				"bad pam password attempt for '%s'",
				ses.authstate.printableuser);
		send_msg_userauth_failure(0, 1);
		goto cleanup;
	}

	/* successful authentication */
	dropbear_log(LOG_NOTICE, "pam password auth succeeded for '%s'",
			ses.authstate.printableuser);
	send_msg_userauth_success();

cleanup:
	if (password != NULL) {
		m_burn(password, passwordlen);
		m_free(password);
	}
	if (pamHandlep != NULL) {
		(void) pam_end(pamHandlep, 0 /* pam_status */);
	}
}
