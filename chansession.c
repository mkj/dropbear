#include "options.h"
#include "packet.h"
#include "buffer.h"
#include "session.h"
#include "util.h"
#include "channel.h"
#include "chansession.h"
#include "sshpty.h"
#include "termcodes.h"
#include "ssh.h"
#include "random.h"

static int sessioncommand(struct Channel *channel, struct ChanSess *chansess,
		char iscmd);
static int sessionpty(struct ChanSess * chansess);
static int sessionsignal(struct ChanSess *chansess);
static int noptycommand(struct Channel *channel, struct ChanSess *chansess);
static int ptycommand(struct Channel *channel, struct ChanSess *chansess);
static int sessionwinchange(struct ChanSess *chansess);
static void execchild(struct ChanSess *chansess);
static void addnewvar(const char* param, const char* var);
static void addchildpid(struct ChanSess *chansess, pid_t pid);
static void sesssigchild_handler(int val);

struct SigMap {
	int signal;
	char* name;
};

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
	{0}
};

/* required to clear environment */
extern char** environ;

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

static void sesssigchild_handler(int val) {

	int status;
	pid_t pid;
	int i;
	struct ChanSess * chansess;
	struct sigaction sa_chld;
	
	TRACE(("enter sigchld handler"));
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {

		/* find the corresponding chansess */
		for (i = 0; i < ses.childpidsize; i++) {
			assert(pid > 1); /* XXX */
			if (ses.childpids[i].pid == pid) {

				assert(ses.childpids[i].chansess != NULL);
				chansess = ses.childpids[i].chansess;
				chansess->exited = 1;
				if (WIFEXITED(status)) {
					chansess->exitstatus = WEXITSTATUS(status);
				}
				if (WIFSIGNALED(status)) {
					chansess->exitsignal = WTERMSIG(status);
					chansess->exitcore = WCOREDUMP(status);
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

void send_msg_chansess_exitsignal(struct Channel * channel,
		struct ChanSess * chansess) {

	int i;
	char* signame = NULL;

	assert(chansess->exited);
	assert(chansess->exitsignal > 0);

	CHECKCLEARTOWRITE();

	/* we check that we can match a signal name, otherwise
	 * don't send anything */
	i = 0;
	while (signames[i].name != 0) {
		if (signames[i].signal == chansess->exitsignal) {
			signame = signames[i].name;
			break;
		}
		i++;
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

/* set up a session type channel */
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

}

/* clean up a session type channel */
void closechansess(struct Channel *channel) {

	struct ChanSess *chansess;
	int i;
	chansess = (struct ChanSess*)channel->typedata;

	TRACE(("enter closechansess"));
	if (chansess == NULL) {
		TRACE(("leave closechansess: chansess == NULL"));
		return;
	}

	m_free(chansess->cmd);
	m_free(chansess->term);
	if (chansess->tty) {
		pty_release(chansess->tty);
	}
	m_free(chansess->tty);

	/* clear child pid entries */
	for (i = 0; i < ses.childpidsize; i++) {
		if (ses.childpids[i].chansess == chansess) {
			assert(ses.childpids[i].pid > 0);
			/* XXX kill the process? or will it die of natural causes? */
			TRACE(("closing pid %d\n", ses.childpids[i].pid));
			TRACE(("exited = %d\n", chansess->exited));
			ses.childpids[i].pid = -1;
			ses.childpids[i].chansess = NULL;
		}
	}
				
	m_free(chansess);

	TRACE(("leave closechansess"));
}

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
		TRACE(("leave chansessionrequest: type too long")); /* XXX error? */
		return;
	}

	chansess = (struct ChanSess*)channel->typedata;
	assert(chansess != NULL);
	TRACE(("type is %s\n", type));

	if (strcmp(type, "exec") == 0) {
		ret = sessioncommand(channel, chansess, 1);
	} else if (strcmp(type, "shell") == 0) {
		ret = sessioncommand(channel, chansess, 0);
	} else if (strcmp(type, "pty-req") == 0) {
		ret = sessionpty(chansess);
	} else if (strcmp(type, "window-change") == 0) {
		ret = sessionwinchange(chansess);
	} else if (strcmp(type, "signal") == 0) {
		ret = sessionsignal(chansess);
	} else {
		/* etc, todo "env", "subsystem", "x11-req" */
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


/* returns 0 on success, 1 otherwise */
static int sessionsignal(struct ChanSess *chansess) {

	int sig = 0;
	unsigned char* signame;
	int i;

	if (chansess->pid == 0) {
		/* haven't got a process pid yet */
		return 1;
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
		return 1;
	}
			
	if (kill(chansess->pid, sig) < 0) {
		return 1;
	} 

	return 0;
}

/* returns 0 on success, 1 on failure */
static int sessionwinchange(struct ChanSess *chansess) {

	if (chansess->master < 0) {
		/* haven't got a pty yet */
		return 1;
	}
			
	chansess->termc = buf_getint(ses.payload);
	chansess->termr = buf_getint(ses.payload);
	chansess->termw = buf_getint(ses.payload);
	chansess->termh = buf_getint(ses.payload);
	
	pty_change_window_size(chansess->master, chansess->termr, chansess->termc,
		chansess->termw, chansess->termh);

	return 0;
}



/* returns 0 on success, 1 on failure */
static int sessionpty(struct ChanSess * chansess) {

	unsigned int termlen;
	unsigned char namebuf[65];
	struct termios termio;

	TRACE(("enter sessionpty"));
	chansess->term = buf_getstring(ses.payload, &termlen);
	if (termlen > MAX_TERM_LEN) {
		/* TODO send disconnect ? */
		TRACE(("leave sessionpty: term len too long"));
		return 1;
	}
	chansess->termc = buf_getint(ses.payload);
	chansess->termr = buf_getint(ses.payload);
	chansess->termw = buf_getint(ses.payload);
	chansess->termh = buf_getint(ses.payload);

	/* allocate the pty */
	assert(chansess->master == -1); /* haven't already got one */
	TRACE(("about to pty_allocate"));
	if (pty_allocate(&chansess->master, &chansess->slave, namebuf, 64) == 0) {
		TRACE(("leave sessionpty: failed to allocate pty"));
		return 1;
	}
	TRACE(("pty_allocate success (probably)"));
	
	chansess->tty = (char*)strdup(namebuf);
	if (!chansess->tty) {
		dropbear_exit("out of memory"); /* TODO disconnect */
	}

	pty_setowner(ses.authstate.pw, chansess->tty);
	TRACE(("done setowner"));
	pty_change_window_size(chansess->master, chansess->termr, chansess->termc,
			chansess->termw, chansess->termh);
	TRACE(("done windowsize"));
	

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
			TRACE(("tcsetattr error"));
		} else {
			TRACE(("tcsetattr success"));
		}
	}

	TRACE(("leave sessionpty"));
	return 0;
	
}

/* returns 0 on sucesss, 1 otherwise */
static int sessioncommand(struct Channel *channel, struct ChanSess *chansess,
		char iscmd) {

	unsigned int cmdlen;

	TRACE(("enter sessioncommand"));

	if (chansess->cmd != NULL) {
		/* TODO - send error - multiple commands? */
		return 1;
	}

	if (iscmd) {
		/* "exec" */
		chansess->cmd = buf_getstring(ses.payload, &cmdlen);

		if (cmdlen > MAX_CMD_LEN) {
			/* TODO - send error - too long ? */
			return 1;
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

/* returns 0 on success, 1 on fail */
static int noptycommand(struct Channel *channel, struct ChanSess *chansess) {

	int infds[2];
	int outfds[2];
	int errfds[2];
	pid_t pid;

	TRACE(("enter noptycommand"));

	/* redirect stdin/stdout/stderr */
	if (pipe(infds) != 0)
		return 1;
	if (pipe(outfds) != 0)
		return 1;
	if (pipe(errfds) != 0)
		return 1;

	pid = fork();
	if (pid < 0)
		return 1;

	if (!pid) {
		/* child */

		/* redirect stdin/stdout */
#define FDIN 0
#define FDOUT 1
		if (dup2(infds[FDIN], STDIN_FILENO) < 0) {
			TRACE(("leave sessioncommand: error redirecting stdin"));
			return 1;
		}
		close(infds[FDOUT]);
		close(infds[FDIN]);

		if (dup2(outfds[FDOUT], STDOUT_FILENO) < 0) {
			TRACE(("leave sessioncommand: error redirecting stdout"));
			return 1;
		}
		close(outfds[FDIN]);
		close(outfds[FDOUT]);

		if (dup2(errfds[FDOUT], STDERR_FILENO) < 0) {
			TRACE(("leave sessioncommand: error redirecting stderr"));
			return 1;
		}
		close(errfds[FDIN]);
		close(errfds[FDOUT]);

		execchild(chansess);
		/* not reached */

	} else {
		/* parent */
		TRACE(("continue sessioncommand: parent"));
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

		if (fcntl(channel->outfd, F_SETFL, O_NONBLOCK) < 0) {
			dropbear_exit("Couldn't set nonblocking");
		}
		if (fcntl(channel->infd, F_SETFL, O_NONBLOCK) < 0) {
			dropbear_exit("Couldn't set nonblocking");
		}
		if (fcntl(channel->errfd, F_SETFL, O_NONBLOCK) < 0) {
			dropbear_exit("Couldn't set nonblocking");
		}
	}
#undef FDIN
#undef FDOUT

	TRACE(("leave noptycommand"));
	return 0;
}

/* returns 0 on success, 1 on fail */
static int ptycommand(struct Channel *channel, struct ChanSess *chansess) {

	pid_t pid;
	

	TRACE(("enter ptycommand"));

	/* we already have a pty allocated */
	assert(chansess->master != -1 && chansess->tty != NULL);
	pid = fork();
	if (pid < 0)
		return 1;

	if (!pid) {
		/* child */
		
		/* redirect stdin/stdout/stderr */
		close(chansess->master);

		pty_make_controlling_tty(&chansess->slave, chansess->tty);
		m_free(chansess->tty);
		
		if (dup2(chansess->slave, STDIN_FILENO) < 0) {
			TRACE(("leave sessioncommand: error redirecting stdin"));
			return 1;
		}

		if (dup2(chansess->slave, STDOUT_FILENO) < 0) {
			TRACE(("leave sessioncommand: error redirecting stdout"));
			return 1;
		}

		if (dup2(chansess->slave, STDERR_FILENO) < 0) {
			TRACE(("leave sessioncommand: error redirecting stderr"));
			return 1;
		}

		close(chansess->slave);

		execchild(chansess);
		/* not reached */

	} else {
		/* parent */
		TRACE(("continue sessioncommand: parent"));
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
	return 0;
}

static void addchildpid(struct ChanSess *chansess, pid_t pid) {

	int i;
	for (i = 0; i < ses.childpidsize; i++) {
		if (ses.childpids[i].pid == -1) {
			break;
		}
	}

	/* need to increase size */
	if (i == ses.childpidsize) {
		ses.childpids = (struct ChildPid*)m_realloc(ses.childpids,
				sizeof(struct ChildPid) * ses.childpidsize+1);
	}
	
	ses.childpids[i].pid = pid;
	ses.childpids[i].chansess = chansess;

}




static void execchild(struct ChanSess *chansess) {

	char *argv[4];
	int i, len;
	int ret;

	/* wipe the hostkey */
	sign_key_free(ses.opts->hostkey);

	/* clear the state of the prng */
	initrandom();

	/* close file descriptors except stdin/stdout/stderr */
	for (i = 3; i < ses.maxfd; i++) {
		/* close() can fail, we need to be sure fds are closed */
		do {
			ret = close(i);
			if (ret < 0 && (errno != EINTR) && (errno != EBADF)) {
				dropbear_exit("error closing file desc");
			}
		} while ((ret < 0) && (errno != EBADF));
	}


	/* clear environment */
	/* if we're debugging using valgrind etc, we need to keep the LD_PRELOAD
	 * etc. this is hazardous, so should only be used for debugging. */
#ifndef DEBUG_KEEP_ENV
#ifdef HAVE_CLEARENV
	clearenv();
#else /* don't HAVE_CLEARENV */
	/*environ = NULL; - won't work */
#endif /* HAVE_CLEARENV */
#endif

	/* change user */
	if (setgid(ses.authstate.pw->pw_gid) < 0) {
		dropbear_exit("error changing user");
	}
#ifndef HACKCRYPT
	/* this will fail if we aren't root - check? XXX*/
	if (initgroups(ses.authstate.pw->pw_name,
				ses.authstate.pw->pw_gid) < 0) {
		dropbear_exit("error changing user");
	}
#endif
	if (setuid(ses.authstate.pw->pw_uid) < 0) {
		dropbear_exit("error changing user");
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

	/* set up execution */
	/* shell commandname - the filename portion only */
	len = strlen(ses.authstate.pw->pw_shell);
	for (i = len-1; i > 0; i--) {
		if (ses.authstate.pw->pw_shell[i] == '/') {
			i++;
			break;
		}
	}
	argv[0] = &ses.authstate.pw->pw_shell[i];
	if (chansess->cmd != NULL) {
		argv[1] = "-c";
		argv[2] = chansess->cmd;
		argv[3] = NULL;
	} else {
		argv[1] = NULL;
	}

	execv(ses.authstate.pw->pw_shell, argv);

	/* only reached on error */
	dropbear_exit("child failed");
}
	
static void addnewvar(const char* param, const char* var) {

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
