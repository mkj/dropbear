#include "includes.h"
#include "service.h"
#include "dbutil.h"
#include "packet.h"
#include "buffer.h"
#include "session.h"
#include "ssh.h"

void send_msg_service_request(char* servicename) {

	TRACE(("enter send_msg_service_request: servicename='%s'", servicename));

	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_SERVICE_REQUEST);
	buf_putstring(ses.writepayload, servicename, strlen(servicename));

	encrypt_packet();
	TRACE(("leave send_msg_service_request"));
}

/* This just sets up the state variables right for the main client session loop
 * to deal with */
void recv_msg_service_accept() {

	unsigned char* servicename;
	unsigned int len;

	TRACE(("enter recv_msg_service_accept"));

	servicename = buf_getstring(ses.payload, &len);

	/* ssh-userauth */
	if (cli_ses.state = SERVICE_AUTH_REQ_SENT
			&& len == SSH_SERVICE_USERAUTH_LEN
			&& strncmp(SSH_SERVICE_USERAUTH, servicename, len) == 0) {

		cli_ses.state = SERVICE_AUTH_ACCEPT_RCVD;
		m_free(servicename);
		TRACE(("leave recv_msg_service_accept: done ssh-userauth"));
		return;
	}

	/* ssh-connection */
	if (cli_ses.state = SERVICE_CONN_REQ_SENT
			&& len == SSH_SERVICE_CONNECTION_LEN 
			&& strncmp(SSH_SERVICE_CONNECTION, servicename, len) == 0) {

		if (ses.authstate.authdone != 1) {
			dropbear_exit("request for connection before auth");
		}

		cli_ses.state = SERVICE_CONN_ACCEPT_RCVD;
		m_free(servicename);
		TRACE(("leave recv_msg_service_accept: done ssh-connection"));
		return;
	}

	dropbear_exit("unrecognised service accept");
	/* m_free(servicename); not reached */

}
