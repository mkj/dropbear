#include "options.h"
#include "buffer.h"
#include "util.h"
#include "channel.h"
#include "chansession.h"
#include "session.h"

static const char * minusslashdev(const unsigned char * tty);
static char * getttyid(char * dest, int destlen, const unsigned char * tty);

/* login code, for the various types */

#ifdef USE_UTMPLOGIN
static void login_addutmp(struct ChanSess * chansess) {

	struct utmp ut;

	/* clear the memory of the struct */
	m_burn((void*)&ut, sizeof(ut));

	/* we don't need to null terminate entries */
	/* username */
	strncpy(ut.ut_name, ses.authstate.username, sizeof(ut.ut_name));
	dropbear_log(LOG_DEBUG, "name is %s\n", ut.ut_name);

	strncpy(ut.ut_line, chansess->tty, sizeof(ut.ut_line));

#ifdef UTMP_HAS_HOST
	/* remote host if required*/
	getaddrhostname(ut.ut_host, sizeof(ut.ut_host), ses.addrstring);
	dropbear_log(LOG_DEBUG, "host is %s\n", ut.ut_host);
#endif

#ifdef UTMP_HAS_PID
	/* pid of the process */
	ut.ut_pid = getpid();
	dropbear_log(LOG_DEBUG, "pid is %d\n", ut.ut_pid);
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
	ut.ut_addr = ((struct sockaddr_in*)ses.remoteaddr)->sin_addr.s_addr;
#endif

#ifdef UTMP_HAS_ID
	/* mmm, more unixy ugliness */
	getttyid(ut.ut_id, sizeof(ut.ut_id), chansess->tty);
	dropbear_log(LOG_DEBUG, "ut_id is %.4s\n", ut.ut_id);
#endif

	/* now the parts specific to logging in */
	ut.ut_type = USER_PROCESS;
	
	login(&ut);

	dropbear_log(LOG_DEBUG, "line is '%s'", ut.ut_line);
}
#endif

#ifdef USE_UTMPUTMPX
static void utmpx_addutmp(struct ChanSess * chansess) {

}
#endif

#ifdef USE_UTMPUTMP
static void utmp_addutmp(struct ChanSess * chansess) {

}
#endif

void dropbear_addlogin(struct ChanSess * chansess) {

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
static const char * minusslashdev(const unsigned char * tty) {

	int len;

	dropbear_log(LOG_DEBUG, "before len");
	len = strlen(tty);
	dropbear_log(LOG_DEBUG, "len  %d", len);

	
	/* we need to have "/dev/" at the start */
	if ((len <= 5) || (memcmp(tty, "/dev/", 5) != 0)) {
		dropbear_log(LOG_DEBUG, "tty1  %s", tty);
		return tty;
	}

	dropbear_log(LOG_DEBUG, "tty2  %s", tty+5);
	return tty+5;
}

#ifdef UTMP_HAS_ID
/* Get the ut_id. First the "/dev/" is removed, and "tty" as well if it exists.
 * The last destlen bytes of the remainder is the result.
 * The result is truncated to dest, it is only null-terminated if there is
 * space at the end. A pointer to dest is returned */
static char * getttyid(char * dest, int destlen, const unsigned char * tty) {

	int len;
	
	dropbear_log(LOG_DEBUG, "blah");
	tty = minusslashdev(tty);
	dropbear_log(LOG_DEBUG, "blah s %s", tty);
	len = strlen(tty);

	/* if it's of the form "/dev/ttya0", we want the "a0" */
	if (len > 3 && (strncmp(tty, "tty", 3) == 0)) {
		tty += 3;
		len -= 3;
	}

	/* the last destlen bit of tty */
	if (len > destlen) {
		dropbear_log(LOG_DEBUG, "len - destlen = %d\n", len - destlen);
		tty = (tty + len - destlen);
	}
	len = MIN(destlen, len);
	dropbear_log(LOG_DEBUG, "len is %d\n", len);

	memcpy(dest, tty, len);
	if (len < destlen) {
		dest[len] = '\0'; /* null terminate if there's space */
	}
	return dest;
}
#endif

#ifdef USE_UTMPLOGIN
void logout_delutmp(struct ChanSess *chansess) {

		dropbear_log(LOG_WARNING, "doing logout(%s)", 
				(chansess->tty));
	if (logout((chansess->tty)) != 0) {
		dropbear_log(LOG_WARNING, "error with logout(): %s", strerror(errno));
	}

}
#endif

#ifdef USE_UTMPUTMPX
void utmpx_delutmp(struct ChanSess *chansess) {

}
#endif

#ifdef USE_UTMPUTMP
void utmp_delutmp(struct ChanSess *chansess) {

}
#endif

void dropbear_dellogin(struct ChanSess * chansess) {

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
