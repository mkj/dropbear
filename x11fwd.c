#include "options.h"
#include "chansession.h"
#include "channel.h"

#ifndef DISABLE_X11FWD

/* returns 0 on success, 1 otherwise */
int x11req(struct Chansess * chansess) {

	unsigned int singleconn;
	unsigned char *authprot, *authcookie;
	unsigned int screennum;
	unsigned int strlen;

	/* we don't care what the data is, it's just going to pipe to the
	 * user's own xauth */
	singleconn = buf_getint(ses.payload);
	authprot = buf_getstring(ses.payload, NULL);
	authcookie = buf_getstring(ses.payload, NULL);
	screennum = buf_getint(ses.payload);

	/* now need to set up listener */

}
#endif /* DROPBEAR_X11FWD */
