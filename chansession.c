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

#include "includes.h"
#include "packet.h"
#include "buffer.h"
#include "session.h"
#include "dbutil.h"
#include "channel.h"
#include "chansession.h"
#include "sshpty.h"
#include "termcodes.h"
#include "ssh.h"
#include "random.h"
#include "utmp.h"
#include "x11fwd.h"
#include "agentfwd.h"

/* Handles sessions (either shells or programs) requested by the client */

static int sessioncommand(struct Channel *channel, struct ChanSess *chansess,
		int iscmd, int issubsys);
static int sessionpty(struct ChanSess * chansess);
static int sessionsignal(struct ChanSess *chansess);
static int noptycommand(struct Channel *channel, struct ChanSess *chansess);
static int ptycommand(struct Channel *channel, struct ChanSess *chansess);
static int sessionwinchange(struct ChanSess *chansess);
static void execchild(struct ChanSess *chansess);
static void addchildpid(struct ChanSess *chansess, pid_t pid);
static void sesssigchild_handler(int val);

struct SigMap {
	int signal;
	char* name;
};

/* Mapping of signal values to ssh signal strings */
struct SigMap signames[] = {
	{SIGABRT, "ABRT"},
	{SIGALRM, "ALRM"},
	{SIGFPE, "FPE"},
	{SIGHUP, "HUP"},
	{SIGILL, "ILL"},
	{SIGINT, "INT"},
	{SIGKILL, "KILL"},
	{SIGPIPE, "PIPE"},
	{SIGQUIT, "QUIT"},
	{SIGSEGV, "SEGV"},
	{SIGTERM, "TERM"},
	{SIGUSR1, "USR1"},
	{SIGUSR2, "USR2"},
	{0, NULL}
};

/* required to clear environment */
extern char** environ;

/* Set up the general chansession environment, in particular child-exit
 * handling */
void chansessinitialise() {

	struct sigaction sa_chld;

	/* single child process intially */
	ses.childpids = (struct ChildPid*)m_malloc(sizeof(struct ChildPid));
	ses.childpids[0].pid = -1; /* unused */
	ses.childpids[0].chansess = NULL;
	ses.childpidsize = 1;
	sa_chld.sa_handler = sesssigchild_handler;
	sa_chld.sa_flags = SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa_chld, NULL) < 0) {
		dropbear_exit("signal() error");
	}
	
}

/* handler for childs exiting, store the state for return to the client */
static void sesssigchild_handler(int val) {

	int status;
	pid_t pid;
	unsigned int i;
	struct ChanSess * chansess;
	struct sigaction sa_chld;

	TRACE(("enter sigchld handler"));
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {

		/* find the corresponding chansess */
		for (i = 0; i < ses.childpidsize; i++) {
			if (ses.childpids[i].pid == pid) {

				chansess = ses.childpids[i].chansess;
				chansess->exited = 1;
				if (WIFEXITED(status)) {
					chansess->exitstatus = WEXITSTATUS(status);
				}
				if (WIFSIGNALED(status)) {
					chansess->exitsignal = WTERMSIG(status);
#ifndef AIX
					chansess->exitcore = WCOREDUMP(status);
#endif
				} else {
					/* we use this to determine how pid exited */
					chansess->exitsignal = -1;
				}
			}
		}
	}
	sa_chld.sa_handler = sesssigchild_handler;
	sa_chld.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa_chld, NULL);
	TRACE(("leave sigchld handler"));
}

/* send the exitstatus to the client */
void send_msg_chansess_exitstatus(struct Channel * channel,
		struct ChanSess * chansess) {

	assert(chansess->exited);
	assert(chansess->exitsignal == -1);

	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putstring(ses.writepayload, "exit-status", 11);
	buf_putbyte(ses.writepayload, 0); /* boolean FALSE */
	buf_putint(ses.writepayload, chansess->exitstatus);

	encrypt_packet();

}

/* send the signal causing the exit to the client */
void send_msg_chansess_exitsignal(struct Channel * channel,
		struct ChanSess * chansess) {

	int i;
	char* signame = NULL;

	assert(chansess->exited);
	assert(chansess->exitsignal > 0);

	CHECKCLEARTOWRITE();

	/* we check that we can match a signal name, otherwise
	 * don't send anything */
	for (i = 0; signames[i].name != NULL; i++) {
		if (signames[i].signal == chansess->exitsignal) {
			signame = signames[i].name;
			break;
		}
	}

	if (signame == NULL) {
		return;
	}

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putstring(ses.writepayload, "exit-signal", 11);
	buf_putbyte(ses.writepayload, 0); /* boolean FALSE */
	buf_putstring(ses.writepayload, signame, strlen(signame));
	buf_putbyte(ses.writepayload, chansess->exitcore);
	buf_putstring(ses.writepayload, "", 0); /* error msg */
	buf_putstring(ses.writepayload, "", 0); /* lang */

	encrypt_packet();
}

/* set up a session channel */
void newchansess(struct Channel *channel) {

	struct ChanSess *chansess;

	assert(channel->typedata == NULL);

	chansess = (struct ChanSess*)m_malloc(sizeof(struct ChanSess));
	chansess->cmd = NULL;
	chansess->pid = 0;

	/* pty details */
	chansess->master = -1;
	chansess->slave = -1;
	chansess->tty = NULL;
	chansess->term = NULL;
	chansess->termw = 0;
	chansess->termh = 0;
	chansess->termc = 0;
	chansess->termr = 0;

	chansess->exited = 0;

	channel->typedata = chansess;

#ifndef DISABLE_X11FWD
	chansess->x11fd = -1;
	chansess->x11authprot = NULL;
	chansess->x11authcookie = NULL;
#endif

#ifndef DISABLE_AGENTFWD
	chansess->agentfd = -1;
	chansess->agentfile = NULL;
	chansess->agentdir = NULL;
#endif

}

/* clean a session channel */
void closechansess(struct Channel *channel) {

	struct ChanSess *chansess;
	unsigned int i;
	struct logininfo *li;

	chansess = (struct ChanSess*)channel->typedata;

	TRACE(("enter closechansess"));
	if (chansess == NULL) {
		TRACE(("leave closechansess: chansess == NULL"));
		return;
	}

	m_free(chansess->cmd);
	m_free(chansess->term);

	if (chansess->tty) {
		/* write the utmp/wtmp login record */
		li = login_alloc_entry(chansess->pid, ses.authstate.username,
				ses.hostname, chansess->tty);
		login_logout(li);
		login_free_entry(li);

		pty_release(chansess->tty);
		m_free(chansess->tty);
	}

#ifndef DISABLE_X11FWD
	x11cleanup(chansess);
#endif

#ifndef DISABLE_AGENTFWD
	agentcleanup(chansess);
#endif

	/* clear child pid entries */
	for (i = 0; i < ses.childpidsize; i++) {
		if (ses.childpids[i].chansess == chansess) {
			assert(ses.childpids[i].pid > 0);
			TRACE(("closing pid %d\n", ses.childpids[i].pid));
			TRACE(("exited = %d\n", chansess->exited));
			ses.childpids[i].pid = -1;
			ses.childpids[i].chansess = NULL;
		}
	}
				
	m_free(chansess);

	TRACE(("leave closechansess"));
}

/* Handle requests for a channel. These can be execution requests,
 * or x11/authagent forwarding. These are passed to appropriate handlers */
void chansessionrequest(struct Channel *channel) {

	unsigned char * type;
	unsigned int typelen;
	unsigned char wantreply;
	int ret = 1;
	struct ChanSess *chansess;

	TRACE(("enter chansessionrequest"));

	assert(channel->type == CHANNEL_ID_SESSION);

	type = buf_getstring(ses.payload, &typelen);
	wantreply = buf_getbyte(ses.payload);

	if (typelen > MAX_NAME_LEN) {
		send_msg_channel_failure(channel);
		m_free(type);
		TRACE(("leave chansessionrequest: type too long")); /* XXX send error?*/
		return;
	}

	chansess = (struct ChanSess*)channel->typedata;
	assert(chansess != NULL);
	TRACE(("type is %s\n", type));

	if (strcmp(type, "window-change") == 0) {
		ret = sessionwinchange(chansess);
	} else if (strcmp(type, "shell") == 0) {
		ret = sessioncommand(channel, chansess, 0, 0);
	} else if (strcmp(type, "pty-req") == 0) {
		ret = sessionpty(chansess);
	} else if (strcmp(type, "exec") == 0) {
		ret = sessioncommand(channel, chansess, 1, 0);
	} else if (strcmp(type, "subsystem") == 0) {
		ret = sessioncommand(channel, chansess, 1, 1);
#ifndef DISABLE_X11FWD
	} else if (strcmp(type, "x11-req") == 0) {
		ret = x11req(chansess);
#endif
#ifndef DISABLE_AGENTFWD
	} else if (strcmp(type, "auth-agent-req@openssh.com") == 0) {
		ret = agentreq(chansess);
#endif
	} else if (strcmp(type, "signal") == 0) {
		ret = sessionsignal(chansess);
	} else {
		/* etc, todo "env", "subsystem" */
	}

	if (wantreply) {
		if (ret == 0) {
			send_msg_channel_success(channel);
		} else {
			send_msg_channel_failure(channel);
		}
	}

	m_free(type);
	TRACE(("leave chansessionrequest"));
}


/* Send a signal to a session's process as requested by the client*/
static int sessionsignal(struct ChanSess *chansess) {

	int sig = 0;
	unsigned char* signame;
	int i;

	if (chansess->pid == 0) {
		/* haven't got a process pid yet */
		return DROPBEAR_FAILURE;
	}

	signame = buf_getstring(ses.payload, NULL);

	i = 0;
	while (signames[i].name != 0) {
		if (strcmp(signames[i].name, signame) == 0) {
			sig = signames[i].signal;
			break;
		}
		i++;
	}

	m_free(signame);

	if (sig == 0) {
		/* failed */
		return DROPBEAR_FAILURE;
	}
			
	if (kill(chansess->pid, sig) < 0) {
		return DROPBEAR_FAILURE;
	} 

	return DROPBEAR_SUCCESS;
}

/* Let the process know that the window size has changed, as notified from the
 * client. Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int sessionwinchange(struct ChanSess *chansess) {

	if (chansess->master < 0) {
		/* haven't got a pty yet */
		return DROPBEAR_FAILURE;
	}
			
	chansess->termc = buf_getint(ses.payload);
	chansess->termr = buf_getint(ses.payload);
	chansess->termw = buf_getint(ses.payload);
	chansess->termh = buf_getint(ses.payload);
	
	pty_change_window_size(chansess->master, chansess->termr, chansess->termc,
		chansess->termw, chansess->termh);

	return DROPBEAR_FAILURE;
}

/* Set up a session pty which will be used to execute the shell or program.
 * The pty is allocated now, and kept for when the shell/program executes.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int sessionpty(struct ChanSess * chansess) {

	unsigned int termlen;
	unsigned char namebuf[65];
	struct termios termio;

	TRACE(("enter sessionpty"));
	chansess->term = buf_getstring(ses.payload, &termlen);
	if (termlen > MAX_TERM_LEN) {
		/* TODO send disconnect ? */
		TRACE(("leave sessionpty: term len too long"));
		return DROPBEAR_FAILURE;
	}
	chansess->termc = buf_getint(ses.payload);
	chansess->termr = buf_getint(ses.payload);
	chansess->termw = buf_getint(ses.payload);
	chansess->termh = buf_getint(ses.payload);

	/* allocate the pty */
	assert(chansess->master == -1); /* haven't already got one */
	if (pty_allocate(&chansess->master, &chansess->slave, namebuf, 64) == 0) {
		TRACE(("leave sessionpty: failed to allocate pty"));
		return DROPBEAR_FAILURE;
	}
	
	chansess->tty = (char*)strdup(namebuf);
	if (!chansess->tty) {
		dropbear_exit("out of memory"); /* TODO disconnect */
	}

	pty_setowner(ses.authstate.pw, chansess->tty);
	pty_change_window_size(chansess->master, chansess->termr, chansess->termc,
			chansess->termw, chansess->termh);

	/* Term modes */
	/* We'll ignore errors and continue if we can't set modes.
	 * We're ignoring baud rates since they seem evil */
	if (tcgetattr(chansess->master, &termio) == 0) {
		unsigned char opcode;
		unsigned int value;
		const struct TermCode * termcode;

		while (((opcode = buf_getbyte(ses.payload)) != 0x00) &&
				opcode <= 159) {
			/* handle types of code */
			if (opcode > MAX_TERMCODE) {
				continue;
			}
			termcode = &termcodes[(unsigned int)opcode];
			
			value = buf_getint(ses.payload);

			switch (termcode->type) {

				case TERMCODE_NONE:
					break;

				case TERMCODE_CONTROLCHAR:
					termio.c_cc[termcode->mapcode] = value;
					break;

				case TERMCODE_INPUT:
					if (value) {
						termio.c_iflag |= termcode->mapcode;
					} else {
						termio.c_iflag &= ~(termcode->mapcode);
					}
					break;

				case TERMCODE_OUTPUT:
					if (value) {
						termio.c_oflag |= termcode->mapcode;
					} else {
						termio.c_oflag &= ~(termcode->mapcode);
					}
					break;

				case TERMCODE_LOCAL:
					if (value) {
						termio.c_lflag |= termcode->mapcode;
					} else {
						termio.c_lflag &= ~(termcode->mapcode);
					}
					break;

				case TERMCODE_CONTROL:
					if (value) {
						termio.c_cflag |= termcode->mapcode;
					} else {
						termio.c_cflag &= ~(termcode->mapcode);
					}
					break;
					
			}
		}
		if (tcsetattr(chansess->master, TCSANOW, &termio) < 0) {
			dropbear_log(LOG_INFO, "error setting terminal attributes");
		}
	}

	TRACE(("leave sessionpty"));
	return DROPBEAR_SUCCESS;
}

/* Handle a command request from the client. This is used for both shell
 * and command-execution requests, and passes the command to
 * noptycommand or ptycommand as appropriate.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int sessioncommand(struct Channel *channel, struct ChanSess *chansess,
		int iscmd, int issubsys) {

	unsigned int cmdlen;

	TRACE(("enter sessioncommand"));

	if (chansess->cmd != NULL) {
		/* TODO - send error - multiple commands? */
		return DROPBEAR_FAILURE;
	}

	if (iscmd) {
		/* "exec" */
		chansess->cmd = buf_getstring(ses.payload, &cmdlen);

		if (cmdlen > MAX_CMD_LEN) {
			/* TODO - send error - too long ? */
			return DROPBEAR_FAILURE;
		}
		if (issubsys) {
#ifdef SFTPSERVER_PATH
			if ((cmdlen == 4) && strncmp(chansess->cmd, "sftp", 4) == 0) {
				m_free(chansess->cmd);
				chansess->cmd = strdup(SFTPSERVER_PATH);
			} else 
#endif
			{
				return DROPBEAR_FAILURE;
			}
		}
	}

	if (chansess->term == NULL) {
		/* no pty */
		return noptycommand(channel, chansess);
	} else {
		/* want pty */
		 return ptycommand(channel, chansess);
	}
}

/* Execute a command and set up redirection of stdin/stdout/stderr without a
 * pty.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int noptycommand(struct Channel *channel, struct ChanSess *chansess) {

	int infds[2];
	int outfds[2];
	int errfds[2];
	pid_t pid;

	TRACE(("enter noptycommand"));

	/* redirect stdin/stdout/stderr */
	if (pipe(infds) != 0)
		return DROPBEAR_FAILURE;
	if (pipe(outfds) != 0)
		return DROPBEAR_FAILURE;
	if (pipe(errfds) != 0)
		return DROPBEAR_FAILURE;

	pid = fork();
	if (pid < 0)
		return DROPBEAR_FAILURE;

	if (!pid) {
		/* child */

		/* redirect stdin/stdout */
#define FDIN 0
#define FDOUT 1
		if ((dup2(infds[FDIN], STDIN_FILENO) < 0) ||
			(dup2(outfds[FDOUT], STDOUT_FILENO) < 0) ||
			(dup2(errfds[FDOUT], STDERR_FILENO) < 0)) {
			TRACE(("leave noptycommand: error redirecting FDs"));
			return DROPBEAR_FAILURE;
		}

		close(infds[FDOUT]);
		close(infds[FDIN]);
		close(outfds[FDIN]);
		close(outfds[FDOUT]);
		close(errfds[FDIN]);
		close(errfds[FDOUT]);

		execchild(chansess);
		/* not reached */

	} else {
		/* parent */
		TRACE(("continue noptycommand: parent"));
		chansess->pid = pid;

		/* add a child pid */
		addchildpid(chansess, pid);

		close(infds[FDIN]);
		close(outfds[FDOUT]);
		close(errfds[FDOUT]);
		channel->infd = infds[FDOUT];
		channel->outfd = outfds[FDIN];
		channel->errfd = errfds[FDIN];
		ses.maxfd = MAX(ses.maxfd, channel->infd);
		ses.maxfd = MAX(ses.maxfd, channel->outfd);
		ses.maxfd = MAX(ses.maxfd, channel->errfd);

		if ((fcntl(channel->outfd, F_SETFL, O_NONBLOCK) < 0) ||
			(fcntl(channel->infd, F_SETFL, O_NONBLOCK) < 0) ||
			(fcntl(channel->errfd, F_SETFL, O_NONBLOCK) < 0)) {
			dropbear_exit("Couldn't set nonblocking");
		}
	}
#undef FDIN
#undef FDOUT

	TRACE(("leave noptycommand"));
	return DROPBEAR_SUCCESS;
}

/* Execute a command or shell within a pty environment, and set up
 * redirection as appropriate.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int ptycommand(struct Channel *channel, struct ChanSess *chansess) {

	pid_t pid;
	struct logininfo *li;
#ifdef DO_MOTD
	buffer * motdbuf = NULL;
	int len;
	struct stat sb;
	char hushpath[MAXPATHLEN];
#endif

	TRACE(("enter ptycommand"));

	/* we already have a pty allocated */
	assert(chansess->master != -1 && chansess->tty != NULL);
	pid = fork();
	if (pid < 0)
		return DROPBEAR_FAILURE;

	if (pid == 0) {
		/* child */
		
		/* redirect stdin/stdout/stderr */
		close(chansess->master);

		pty_make_controlling_tty(&chansess->slave, chansess->tty);
		
		if ((dup2(chansess->slave, STDIN_FILENO) < 0) ||
			(dup2(chansess->slave, STDERR_FILENO) < 0) ||
			(dup2(chansess->slave, STDOUT_FILENO) < 0)) {
			TRACE(("leave ptycommand: error redirecting filedesc"));
			return DROPBEAR_FAILURE;
		}

		close(chansess->slave);

		/* write the utmp/wtmp login record - must be after changing the
		 * terminal used for stdout with the dup2 above */
		li= login_alloc_entry(getpid(), ses.authstate.username,
				ses.hostname, chansess->tty);
		login_login(li);
		login_free_entry(li);

		m_free(chansess->tty);

#ifdef DO_MOTD
		if (ses.opts->domotd) {
			/* don't show the motd if ~/.hushlogin exists */
			strlcpy(hushpath, ses.authstate.pw->pw_dir, sizeof(hushpath));
			strlcat(hushpath, "/.hushlogin", sizeof(hushpath));

			if (stat(hushpath, &sb) < 0) {
				/* more than a screenful is stupid IMHO */
				motdbuf = buf_new(80 * 25);
				if (buf_readfile(motdbuf, MOTD_FILENAME) == DROPBEAR_SUCCESS) {
					buf_setpos(motdbuf, 0);
					while (motdbuf->pos != motdbuf->len) {
						len = motdbuf->len - motdbuf->pos;
						len = write(STDOUT_FILENO, 
								buf_getptr(motdbuf, len), len);
						buf_incrpos(motdbuf, len);
					}
				}
				buf_free(motdbuf);
			}
		}
#endif /* DO_MOTD */

		execchild(chansess);
		/* not reached */

	} else {
		/* parent */
		TRACE(("continue ptycommand: parent"));
		chansess->pid = pid;

		/* add a child pid */
		addchildpid(chansess, pid);

		close(chansess->slave);
		channel->infd = chansess->master;
		channel->outfd = chansess->master;
		/* don't need to set stderr here */
		ses.maxfd = MAX(ses.maxfd, chansess->master);

		if (fcntl(chansess->master, F_SETFL, O_NONBLOCK) < 0) {
			dropbear_exit("Couldn't set nonblocking");
		}

	}

	TRACE(("leave ptycommand"));
	return DROPBEAR_SUCCESS;
}

/* Add the pid of a child to the list for exit-handling */
static void addchildpid(struct ChanSess *chansess, pid_t pid) {

	unsigned int i;
	for (i = 0; i < ses.childpidsize; i++) {
		if (ses.childpids[i].pid == -1) {
			break;
		}
	}

	/* need to increase size */
	if (i == ses.childpidsize) {
		ses.childpids = (struct ChildPid*)m_realloc(ses.childpids,
				sizeof(struct ChildPid) * ses.childpidsize+1);
		ses.childpidsize++;
	}
	
	ses.childpids[i].pid = pid;
	ses.childpids[i].chansess = chansess;

}

/* Clean up, drop to user privileges, set up the environment and execute
 * the command/shell. This function does not return. */
static void execchild(struct ChanSess *chansess) {

	char *argv[4];
	char * usershell;
	char * baseshell;
	unsigned int i;

	/* wipe the hostkey */
	sign_key_free(ses.opts->hostkey);
	ses.opts->hostkey = NULL;

	/* overwrite the prng state */
	seedrandom();

	/* close file descriptors except stdin/stdout/stderr
	 * Need to be sure FDs are closed here to avoid reading files as root */
	for (i = 3; i < (unsigned int)ses.maxfd; i++) {
		if (m_close(i) == DROPBEAR_FAILURE) {
			dropbear_exit("Error closing file desc");
		}
	}

	/* clear environment */
	/* if we're debugging using valgrind etc, we need to keep the LD_PRELOAD
	 * etc. This is hazardous, so should only be used for debugging. */
#ifndef DEBUG_KEEP_ENV
#ifdef HAVE_CLEARENV
	clearenv();
#else /* don't HAVE_CLEARENV */
	/* Yay for posix. */
	if (environ) {
		environ[0] = NULL;
	}
#endif /* HAVE_CLEARENV */
#endif /* DEBUG_KEEP_ENV */

	/* We can only change uid/gid as root ... */
	if (getuid() == 0) {

		if ((setgid(ses.authstate.pw->pw_gid) < 0) ||
			(initgroups(ses.authstate.pw->pw_name, 
						ses.authstate.pw->pw_gid) < 0) ||
			(setuid(ses.authstate.pw->pw_uid) < 0)) {
			dropbear_exit("error changing user");
		}
	} else {
		/* ... but if the daemon is the same uid as the requested uid, we don't
		 * need to */

		/* XXX - there is a minor issue here, in that if there are multiple
		 * usernames with the same uid, but differing groups, then the
		 * differing groups won't be set (as with initgroups()). The solution
		 * is for the sysadmin not to give out the UID twice */
		if (getuid() != ses.authstate.pw->pw_uid) {
			dropbear_exit("couldn't	change user as non-root");
		}
	}

	/* set env vars */
	addnewvar("USER", ses.authstate.pw->pw_name);
	addnewvar("LOGNAME", ses.authstate.pw->pw_name);
	addnewvar("HOME", ses.authstate.pw->pw_dir);
	addnewvar("SHELL", ses.authstate.pw->pw_shell);
	if (chansess->term != NULL) {
		addnewvar("TERM", chansess->term);
	}

	/* change directory */
	if (chdir(ses.authstate.pw->pw_dir) < 0) {
		dropbear_exit("error changing directory");
	}

#ifndef DISABLE_X11FWD
	/* set up X11 forwarding if enabled */
	x11setauth(chansess);
#endif
#ifndef DISABLE_AGENTFWD
	/* set up agent env variable */
	agentset(chansess);
#endif

	/* an empty shell should be interpreted as "/bin/sh" */
	if (ses.authstate.pw->pw_shell[0] == '\0') {
		usershell = "/bin/sh";
	} else {
		usershell = ses.authstate.pw->pw_shell;
	}

	baseshell = basename(usershell);

	if (chansess->cmd != NULL) {
		argv[0] = baseshell;
	} else {
		/* a login shell should be "-bash" for "/bin/bash" etc */
		argv[0] = (char*)m_malloc(strlen(baseshell) + 2); /* 2 for "-" */
		strcpy(argv[0], "-");
		strcat(argv[0], baseshell);
	}

	if (chansess->cmd != NULL) {
		argv[1] = "-c";
		argv[2] = chansess->cmd;
		argv[3] = NULL;
	} else {
		/* construct a shell of the form "-bash" etc */
		argv[1] = NULL;
	}

	execv(ses.authstate.pw->pw_shell, argv);

	/* only reached on error */
	dropbear_exit("child failed");
}
	
/* add a new environment variable, allocating space for the entry */
void addnewvar(const char* param, const char* var) {

	char* newvar;
	int plen, vlen;

	plen = strlen(param);
	vlen = strlen(var);

	newvar = m_malloc(plen + vlen + 2); /* 2 is for '=' and '\0' */
	memcpy(newvar, param, plen);
	newvar[plen] = '=';
	memcpy(&newvar[plen+1], var, vlen);
	newvar[plen+vlen+1] = '\0';
	if (putenv(newvar) < 0) {
		dropbear_exit("environ error");
	}
}
