#ifndef _X11FWD_H_
#define _X11FWD_H_
#ifndef DISABLE_X11FWD

#include "options.h"
#include "chansession.h"
#include "channel.h"

int x11req(struct Chansess * chansess);

#endif /* DROPBEAR_X11FWD */
#endif /* _X11FWD_H_ */
