#ifndef _CHANSESSION_H_
#define _CHANSESSION_H_

#include <sys/types.h>
#include <unistd.h>

struct ChanSess {

	unsigned char * cmd; /* command to exec */
	pid_t pid; /* child process pid */

	int errfd; /* stderr only exists for sessions */

	/* pty details */
	int master; /* the master terminal fd*/
	int slave;
	unsigned char * tty;

	unsigned char * term;
	unsigned int termw, termh, termc, termr; /* width, height, col, rows */

	/* exit details */
	int exited;
	int exitstatus;
	int exitsignal;
	unsigned char exitcore;
	
};

struct ChildPid {
	pid_t pid;
	struct ChanSess * chansess;
};


void newchansess(struct Channel * channel);
void chansessionrequest(struct Channel * channel);
void closechansess(struct Channel * channel);
void chansessinitialise();
void send_msg_chansess_exitstatus(struct Channel * channel,
		struct ChanSess * chansess);
void send_msg_chansess_exitsignal(struct Channel * channel,
		struct ChanSess * chansess);


#define MAX_CMD_LEN 256 /* XXX */
#define MAX_TERM_LEN 200 /* XXX */

#endif /* _CHANSESSION_H_ */
