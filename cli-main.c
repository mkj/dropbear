#include <includes.h>

int main(int argc, char ** argv) {

	int sock;
	char* error = NULL;
	char* hostandport;
	int len;

	_dropbear_exit = cli_dropbear_exit;
	_dropbear_log = cli_dropbear_log;

	cli_getopts(argc, argv);

	sock = connect_remote(cli_opts.remotehost, cli_opts.remoteport, 
			0, &error);

	if (sock < 0) {
		dropbear_exit("%s", error);
	}

	/* Set up the host:port log */
	len = strlen(cli_opts.remotehost);
	len += 10; /* 16 bit port and leeway*/
	hostandport = (char*)m_malloc(len);
	snprintf(hostandport, len, "%s%d", 
			cli_opts.remotehost, cli_opts.remoteport);

	cli_session(sock, hostandport);

	/* not reached */
	return -1;
}
