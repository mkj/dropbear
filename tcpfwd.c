#include "tcpfwd.h"

int newdirecttcp(struct Channel * chan) {

	unsigned char* desthost;
	unsigned int destport;
	unsigned char* orighost;
	unsigned int origport;

	desthost = buf_getstring(ses.payload);
	destport = buf_getport(ses.payload);
	orighost = buf_getstring(ses.payload);
	origport = buf_getstring(ses.payload);

	/* need to make sure that our origport matches the range of the
	 * source origport */

}
