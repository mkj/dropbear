#ifndef _X11FWD_H_
#define _X11FWD_H_
#ifndef DISABLE_X11FWD

#include "options.h"
#include "chansession.h"
#include "channel.h"

int x11req(struct ChanSess * chansess);
int x11accept(struct ChanSess * chansess);
void x11cleanup(struct ChanSess * chansess);
void x11setauth(struct ChanSess *chansess);

#endif /* DROPBEAR_X11FWD */
#endif /* _X11FWD_H_ */
