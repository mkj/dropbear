#ifndef _AGENTFWD_H_
#define _AGENTFWD_H_
#ifndef DISABLE_AGENTFWD

#include "options.h"
#include "chansession.h"
#include "channel.h"

int agentreq(struct ChanSess * chansess);
int agentaccept(struct ChanSess * chansess);
void agentcleanup(struct ChanSess * chansess);
void agentsetauth(struct ChanSess *chansess);

#endif /* DROPBEAR_AGENTFWD */
#endif /* _AGENTFWD_H_ */
