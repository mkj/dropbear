#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include <sys/types.h>

#define CHANNEL_TYPE_SESSION "session"
#define CHANNEL_TYPE_X11 "x11"

#define CHANNEL_ID_NONE 0
#define CHANNEL_ID_SESSION 1
#define CHANNEL_ID_X11 2

#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED    1
#define SSH_OPEN_CONNECT_FAILED                 2
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE           3
#define SSH_OPEN_RESOURCE_SHORTAGE              4

#define MAX_CHANNELS 1000 /* arbitrary */
#define CHAN_EXTEND_SIZE 3 /* how many extra slots to add when we need more */

#define RECV_MAXWINDOW 6000 /* tweak */
#define RECV_MAXPACKET 1400 /* tweak */
#define RECV_MINWINDOW 10000 /* when we get below this, we send a windowadjust*/

struct Channel {

	unsigned int index; /* the local channel index */
	unsigned int remotechan;
	char type; /* session, x11, forwarded/direct-tcpip */
	unsigned int recvwindow, transwindow;
	unsigned int recvmaxpacket, transmaxpacket;
	void* typedata; /* a pointer to type specific data */
	int infd; /* stdin for the program, we write to this */
	int outfd; /* stdout for the program, we read from this */
	int errfd; /* stdout for a program. This doesn't really fit here,
				  but makes the code a lot tidyer without being too bad. This
				  is -1 for channels which don't requre it. Currently only
				  a 'session' without a pty will use it */
	buffer *writebuf; /* data for the program */

	int sentclosed;
	/* whether we've reached the end of reading/writing to/from/err for a pipe
	 * or program */
	int transeof, recveof, erreof; 

};
	
void chaninitialise();
void chancleanup();
void setchannelfds(fd_set *readfd, fd_set *writefd);
void channelio(fd_set *readfd, fd_set *writefd);

void recv_msg_channel_open();
void recv_msg_channel_request();
void send_msg_channel_failure(struct Channel *channel);
void send_msg_channel_success(struct Channel *channel);
void recv_msg_channel_data();
void recv_msg_channel_window_adjust();
void recv_msg_channel_close();
void recv_msg_channel_eof();


#endif /* _CHANNEL_H_ */
