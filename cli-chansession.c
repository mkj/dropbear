#include "includes.h"
#include "packet.h"
#include "buffer.h"
#include "session.h"
#include "dbutil.h"
#include "channel.h"
#include "ssh.h"
#include "runopts.h"

static void cli_closechansess(struct Channel *channel);
static int cli_initchansess(struct Channel *channel);

static void start_channel_request(struct Channel *channel, unsigned char *type);

static void send_chansess_pty_req(struct Channel *channel);
static void send_chansess_shell_req(struct Channel *channel);

static void cli_tty_setup();
static void cli_tty_cleanup();

static const struct ChanType clichansess = {
	0, /* sepfds */
	"session", /* name */
	cli_initchansess, /* inithandler */
	NULL, /* checkclosehandler */
	NULL, /* reqhandler */
	cli_closechansess, /* closehandler */
};

/* If the main session goes, we close it up */
static void cli_closechansess(struct Channel *channel) {

	/* This channel hasn't gone yet, so we have > 1 */
	if (ses.chancount > 1) {
		dropbear_log(LOG_INFO, "Waiting for other channels to close...");
	}

	cli_tty_cleanup(); /* Restore tty modes etc */

}

static void start_channel_request(struct Channel *channel, 
		unsigned char *type) {

	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
	buf_putint(ses.writepayload, channel->remotechan);

	buf_putstring(ses.writepayload, type, strlen(type));

}


/* Taken from OpenSSH's sshtty.c:
 * RCSID("OpenBSD: sshtty.c,v 1.5 2003/09/19 17:43:35 markus Exp "); */
static void cli_tty_setup() {

	struct termios tio;

	TRACE(("enter cli_pty_setup"));

	if (cli_ses.tty_raw_mode == 1) {
		TRACE(("leave cli_tty_setup: already in raw mode!"));
		return;
	}

	if (tcgetattr(STDIN_FILENO, &tio) == -1) {
		dropbear_exit("Failed to set raw TTY mode");
	}

	/* make a copy */
	cli_ses.saved_tio = tio;

	tio.c_iflag |= IGNPAR;
	tio.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#ifdef IUCLC
	tio.c_iflag &= ~IUCLC;
#endif
	tio.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
#ifdef IEXTEN
	tio.c_lflag &= ~IEXTEN;
#endif
	tio.c_oflag &= ~OPOST;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSADRAIN, &tio) == -1) {
		dropbear_exit("Failed to set raw TTY mode");
	}

	cli_ses.tty_raw_mode = 1;
	TRACE(("leave cli_tty_setup"));
}

static void cli_tty_cleanup() {

	TRACE(("enter cli_tty_cleanup"));

	if (cli_ses.tty_raw_mode == 0) {
		TRACE(("leave cli_tty_cleanup: not in raw mode"));
	}

	if (tcsetattr(STDIN_FILENO, TCSADRAIN, &cli_ses.saved_tio) == -1) {
		dropbear_log(LOG_WARNING, "Failed restoring TTY");
	} else {
		cli_ses.tty_raw_mode = 0; 
	}

	TRACE(("leave cli_tty_cleanup"));
}

static void send_chansess_pty_req(struct Channel *channel) {

	unsigned char* termmodes = "\0";
	unsigned char* term = NULL;
	int termc = 80, termr = 25, termw = 0, termh = 0; /* XXX TODO matt */

	TRACE(("enter send_chansess_pty_req"));
	start_channel_request(channel, "pty-req");

	term = getenv("TERM");
	if (term == NULL) {
		term = "vt100";
	}

	/* XXX TODO */
	buf_putbyte(ses.writepayload, 0); /* Don't want replies */
	buf_putstring(ses.writepayload, term, strlen(term));
	buf_putint(ses.writepayload, termc); /* Cols */
	buf_putint(ses.writepayload, termr); /* Rows */
	buf_putint(ses.writepayload, termw); /* Width */
	buf_putint(ses.writepayload, termh); /* Height */

	buf_putstring(ses.writepayload, termmodes, 1); /* XXX TODO */
	//m_free(termmodes);

	encrypt_packet();
	TRACE(("leave send_chansess_pty_req"));
}

static void send_chansess_shell_req(struct Channel *channel) {

	unsigned char* reqtype = NULL;

	TRACE(("enter send_chansess_shell_req"));

	if (cli_opts.cmd) {
		reqtype = "exec";
	} else {
		reqtype = "shell";
	}

	start_channel_request(channel, reqtype);

	/* XXX TODO */
	buf_putbyte(ses.writepayload, 0); /* Don't want replies */
	if (cli_opts.cmd) {
		buf_putstring(ses.writepayload, cli_opts.cmd, strlen(cli_opts.cmd));
	}

	encrypt_packet();
	TRACE(("leave send_chansess_shell_req"));
}

static int cli_initchansess(struct Channel *channel) {

	channel->infd = STDOUT_FILENO;
	//channel->outfd = STDIN_FILENO;
	//channel->errfd = STDERR_FILENO;

	if (cli_opts.wantpty) {
		send_chansess_pty_req(channel);
	}

	cli_opts.cmd = "df";
	send_chansess_shell_req(channel);

	if (cli_opts.wantpty) {
		cli_tty_setup();
	}

	return 0; /* Success */

}


void cli_send_chansess_request() {

	TRACE(("enter cli_send_chansess_request"));
	if (send_msg_channel_open_init(STDIN_FILENO, &clichansess) 
			== DROPBEAR_FAILURE) {
		dropbear_exit("Couldn't open initial channel");
	}

	/* No special channel request data */
	encrypt_packet();
	TRACE(("leave cli_send_chansess_request"));

}
