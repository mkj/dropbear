
#ifndef _UTMP_H_
#define _UTMP_H_

#include "options.h"
#include "chansession.h"

int dropbear_addlogin(struct ChanSess * chansess);
int dropbear_dellogin(struct ChanSess * chansess);

#endif
