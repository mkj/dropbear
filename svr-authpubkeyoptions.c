/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2008 Frederic Moulins
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
 * SOFTWARE. 
 *
 * This file incorporates work covered by the following copyright and  
 * permission notice:
 *
 * 	Author: Tatu Ylonen <ylo@cs.hut.fi>
 * 	Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 * 	              All rights reserved
 * 	As far as I am concerned, the code I have written for this software
 * 	can be used freely for any purpose.  Any derived versions of this
 * 	software must be clearly marked as such, and if the derived work is
 * 	incompatible with the protocol description in the RFC file, it must be
 * 	called by a name other than "ssh" or "Secure Shell".
 *
 * This copyright and permission notice applies to the code parsing public keys
 * options string which can also be found in OpenSSH auth-options.c file 
 * (auth_parse_options).
 *
 */

/* Process pubkey options during a pubkey auth request */
#include "includes.h"
#include "session.h"
#include "dbutil.h"
#include "signkey.h"
#include "auth.h"

#ifdef ENABLE_SVR_PUBKEY_OPTIONS

/* Returns 1 if pubkey allows agent forwarding,
 * 0 otherwise */
int svr_pubkey_allows_agentfwd() {
	if (ses.authstate.pubkey_options 
		&& ses.authstate.pubkey_options->no_agent_forwarding_flag) {
		return 0;
	}
	return 1;
}

/* Returns 1 if pubkey allows tcp forwarding,
 * 0 otherwise */
int svr_pubkey_allows_tcpfwd() {
	if (ses.authstate.pubkey_options 
		&& ses.authstate.pubkey_options->no_port_forwarding_flag) {
		return 0;
	}
	return 1;
}

/* Returns 1 if pubkey allows x11 forwarding,
 * 0 otherwise */
int svr_pubkey_allows_x11fwd() {
	if (ses.authstate.pubkey_options 
		&& ses.authstate.pubkey_options->no_x11_forwarding_flag) {
		return 0;
	}
	return 1;
}

/* Returns 1 if pubkey allows pty, 0 otherwise */
int svr_pubkey_allows_pty() {
	if (ses.authstate.pubkey_options 
		&& ses.authstate.pubkey_options->no_pty_flag) {
		return 0;
	}
	return 1;
}

/* Set chansession command to the one forced by 'command' public key option */
void svr_pubkey_set_forced_command(struct ChanSess *chansess) {
	if (ses.authstate.pubkey_options)
		chansess->cmd = ses.authstate.pubkey_options->forced_command;
}

/* Free potential public key options */
void svr_pubkey_options_cleanup() {
	if (ses.authstate.pubkey_options) {
		m_free(ses.authstate.pubkey_options);
		ses.authstate.pubkey_options = NULL;
	}
}

/* Parse pubkey options and set ses.authstate.pubkey_options accordingly.
 * Returns DROPBEAR_SUCCESS if key is ok for auth, DROPBEAR_FAILURE otherwise */
int svr_add_pubkey_options(const char* opts) {
	const char *cp;
	int i;
	int ret = DROPBEAR_FAILURE;

	TRACE(("enter addpubkeyoptions"))

	if (!opts || *opts == ' ') {
		/* no option, success */
		ret = DROPBEAR_SUCCESS;
		goto end;
	}
	
	ses.authstate.pubkey_options = (struct PubKeyOptions*)m_malloc(sizeof( struct PubKeyOptions ));

	while (*opts && *opts != ' ' && *opts != '\t') {
		cp = "no-port-forwarding";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			dropbear_log(LOG_WARNING, "Port forwarding disabled.");
			ses.authstate.pubkey_options->no_port_forwarding_flag = 1;
			opts += strlen(cp);
			goto next_option;
		}
#ifdef ENABLE_AGENTFWD
		cp = "no-agent-forwarding";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			dropbear_log(LOG_WARNING, "Agent forwarding disabled.");
			ses.authstate.pubkey_options->no_agent_forwarding_flag = 1;
			opts += strlen(cp);
			goto next_option;
		}
#endif
#ifdef ENABLE_X11FWD
		cp = "no-X11-forwarding";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			dropbear_log(LOG_WARNING, "X11 forwarding disabled.");
			ses.authstate.pubkey_options->no_x11_forwarding_flag = 1;
			opts += strlen(cp);
			goto next_option;
		}
#endif
		cp = "no-pty";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			dropbear_log(LOG_WARNING, "Pty allocation disabled.");
			ses.authstate.pubkey_options->no_pty_flag = 1;
			opts += strlen(cp);
			goto next_option;
		}
		cp = "command=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			opts += strlen(cp);
			ses.authstate.pubkey_options->forced_command = (char*)m_malloc(strlen(opts) + 1);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					ses.authstate.pubkey_options->forced_command[i++] = '"';
					continue;
				}
				ses.authstate.pubkey_options->forced_command[i++] = *opts++;
			}
			if (!*opts) {
				dropbear_log(LOG_WARNING, 
						"Missing end quote in public key command option");
				m_free(ses.authstate.pubkey_options->forced_command);
				ses.authstate.pubkey_options->forced_command = NULL;
				goto bad_option;
			}
			ses.authstate.pubkey_options->forced_command[i] = '\0';
			if (strlen(ses.authstate.pubkey_options->forced_command) > MAX_CMD_LEN) {
				dropbear_log(LOG_WARNING, 
						"Public key option command too long (>MAX_CMD_LEN).");
				m_free(ses.authstate.pubkey_options->forced_command);
				ses.authstate.pubkey_options->forced_command = NULL;
				goto bad_option;
			}
			dropbear_log(LOG_WARNING, "Forced command '%s'", 
				ses.authstate.pubkey_options->forced_command);
			opts++;
			goto next_option;
		}
		next_option:
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		if (!*opts) {
			TRACE(("Bugs in svr-chansession.c pubkey option processing."))
		}
		if (*opts == ' ' || *opts == '\t') {
			break;		/* End of options. */
		}
		if (*opts != ',') {
			goto bad_option;
		}
		opts++;
		/* Process the next option. */
	}
	/* parsed all options with no problem */
	ret = DROPBEAR_SUCCESS;
	goto end;

bad_option:
	ret = DROPBEAR_FAILURE;
	m_free(ses.authstate.pubkey_options);
	ses.authstate.pubkey_options = NULL;
	dropbear_log(LOG_WARNING, "Bad public key options : '%.50s'", opts);

end:
	TRACE(("leave addpubkeyoptions"))
	return ret;

}

#endif
