#include "includes.h"
#include "dbutil.h"
#include "runopts.h"
#include "session.h"

static void cli_dropbear_exit(int exitcode, const char* format, va_list param);
static void cli_dropbear_log(int priority, const char* format, va_list param);

#if defined(DBMULTI_dbclient) || !defined(DROPBEAR_MULTI)
#if defined(DBMULTI_dbclient) && defined(DROPBEAR_MULTI)
int cli_main(int argc, char ** argv) {
#else
int main(int argc, char ** argv) {
#endif

	int sock;
	char* error = NULL;
	char* hostandport;
	int len;

	_dropbear_exit = cli_dropbear_exit;
	_dropbear_log = cli_dropbear_log;

	cli_getopts(argc, argv);

	TRACE(("user='%s' host='%s' port='%s'", cli_opts.username,
				cli_opts.remotehost, cli_opts.remoteport));

	sock = connect_remote(cli_opts.remotehost, cli_opts.remoteport, 
			0, &error);

	if (sock < 0) {
		dropbear_exit("%s", error);
	}

	/* Set up the host:port log */
	len = strlen(cli_opts.remotehost);
	len += 10; /* 16 bit port and leeway*/
	hostandport = (char*)m_malloc(len);
	snprintf(hostandport, len, "%s:%s", 
			cli_opts.remotehost, cli_opts.remoteport);

	cli_session(sock, hostandport);

	/* not reached */
	return -1;
}
#endif /* DBMULTI stuff */

static void cli_dropbear_exit(int exitcode, const char* format, va_list param) {

	char fmtbuf[300];

	if (!sessinitdone) {
		snprintf(fmtbuf, sizeof(fmtbuf), "exited: %s",
				format);
	} else {
		snprintf(fmtbuf, sizeof(fmtbuf), 
				"connection to %s@%s:%s exited: %s", 
				cli_opts.username, cli_opts.remotehost, 
				cli_opts.remoteport, format);
	}

	_dropbear_log(LOG_INFO, fmtbuf, param);

	common_session_cleanup();
	exit(exitcode);
}

static void cli_dropbear_log(int priority, const char* format, va_list param) {

	char printbuf[1024];

	vsnprintf(printbuf, sizeof(printbuf), format, param);

	fprintf(stderr, "Dropbear: %s\n", printbuf);

}
