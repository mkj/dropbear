#include "options.h"
#include "buffer.h"
#include "util.h"
#include "channel.h"
#include "chansession.h"
#include "session.h"

/* login code, for the various types */

#ifdef USE_UTMPLOGIN
static int login_addutmp(struct ChanSess * chansess) {

	struct utmp ut;

	/* clear the memory of the struct */
	m_burn((void*)&ut);

	/* we don't need to null terminate entries */
	/* username */
	strncpy(ut.ut_name, ses.authstate.username, sizeof(ut.ut_name));

	/* terminal device minus the "/dev/" */
	strncpy(ut.ut_line, minusslashdev(chansess->tty), sizeof(ut.ut_line);

#ifdef UTMP_HAS_HOST
	/* remote host if required*/
	getaddrhostname(ut.ut_host, sizeof(ut.ut_host), ses.addrstring);
#endif

#ifdef UTMP_HAS_PID
	/* pid of the process */
	ut.ut_pid = chansess->pid;
#endif

#ifdef UTMP_HAS_TIME
	/* time in seconds */
	time(&ut.ut_time);
#endif

#ifdef UTMP_HAS_TV
	gettimeofday(&ut.ut_tv, NULL);
#endif

#ifdef UTMP_HAS_ADDR
	/* XXX - will require change for ip6 */
	ut.ut_addr = ses.remoteaddr->sin_addr.s_addr;
#endif

#ifdef UTMP_HAS_ID
	/* mmm, more unixy ugliness */
	getttyid(ut.ut_id, sizeof(ut.ut_id), chansess->tty));
#endif

	/* now the parts specific to logging in */
	ut.ut_type = USER_PROCESS;
	
	login(&ut);
}
#endif

#ifdef USE_UTMPUTMPX
static int utmpx_addutmp(struct ChanSess * chansess) {

}
#endif

#ifdef USE_UTMPUTMP
static int utmp_addutmp(struct ChanSess * chansess) {

}
#endif

int dropbear_addlogin(struct ChanSess * chansess) {

#ifdef USE_UTMPLOGIN
	return login_addutmp(chansess);
#endif

#ifdef USE_UTMPUTMPX
	return utmpx_addutmp(chansess);
#endif

#ifdef USE_UTMPUTMP
	return utmp_addutmp(chansess);
#endif

	/* not reached */
	assert(0);
	
}

/* return a string minus the "/dev/" */
static char * minusslashdev(unsigned char * tty) {

	int len;

	len = strlen(tty);
	
	/* we need to have "/dev/" at the start */
	if ((len <= 5) || (strncmp(tty, "/dev/", 5) != 0)) {
		return tty;
	}

	return (char*)tty+5;
}

#ifdef USE_UTMP_ID
static char * getttyid(char * dest, int destlen,
		unsigned char * tty) {

	int len;
	
	tty = minusslashdev(tty);
	len = strlen(tty);

	/* if it's of the form "/dev/ttya0", we want the "a0" */
	if (len > 3) {
		tty += 3;
	}

	return tty;
}
#endif

#ifdef USE_UTMPLOGIN
int logout_delutmp(struct ChanSess *chansess) {

	if (logout(minusslashdev(chansess->tty)) != 0) {
		dropbear_log(LOG_WARN, "error with logout()");
	}

}
#endif

#ifdef USE_UTMPUTMPX
int utmpx_delutmp(struct ChanSess *chansess) {

}
#endif

#ifdef USE_UTMPUTMP
int utmp_delutmp(struct ChanSess *chansess) {

}
#endif

int dropbear_dellogin(struct ChanSess * chansess) {

#ifdef USE_UTMPLOGIN
	return logout_delutmp(chansess);
#endif

#ifdef USE_UTMPUTMPX
	return utmpx_delutmp(chansess);
#endif

#ifdef USE_UTMPUTMP
	return utmp_delutmp(chansess);
#endif

	assert(0);

}
