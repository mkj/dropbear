/*
 * Copied from openssh-3.5p1 source
 * 
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Allocating a pseudo-terminal, and making it the controlling tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/*RCSID("$OpenBSD: sshpty.c,v 1.7 2002/06/24 17:57:20 deraadt Exp $");*/

#include "options.h"
#include "util.h"
#include "errno.h"
#include "sshpty.h"

/* Pty allocated with _getpty gets broken if we do I_PUSH:es to it. */
#if defined(HAVE__GETPTY) || defined(HAVE_OPENPTY)
#undef HAVE_DEV_PTMX
#endif

#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#if defined(HAVE_DEV_PTMX) && defined(HAVE_SYS_STROPTS_H)
# include <sys/stropts.h>
#endif

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

/*
 * Allocates and opens a pty.  Returns 0 if no pty could be allocated, or
 * nonzero if a pty was successfully allocated.  On success, open file
 * descriptors for the pty and tty sides and the name of the tty side are
 * returned (the buffer must be able to hold at least 64 characters).
 */

int
pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, int namebuflen)
{
#if defined(HAVE_OPENPTY) || defined(BSD4_4)
	/* openpty(3) exists in OSF/1 and some other os'es */
	char *name;
	int i;

	TRACE(("#if defined(HAVE_OPENPTY) || defined(BSD4_4)"));
	i = openpty(ptyfd, ttyfd, NULL, NULL, NULL);
	if (i < 0) {
		TRACE(("pty_allocate: error with openpty"));
		/*error("openpty: %.100s", strerror(errno)); matt */
		return 0;
	}
	name = ttyname(*ttyfd);
	if (!name) {
		dropbear_exit("openpty returns device for which ttyname fails.");
	}

	strlcpy(namebuf, name, namebuflen);	/* possible truncation */
	return 1;
#else /* HAVE_OPENPTY */
#ifdef HAVE__GETPTY
	/*
	 * _getpty(3) exists in SGI Irix 4.x, 5.x & 6.x -- it generates more
	 * pty's automagically when needed
	 */
	char *slave;
	TRACE(("#ifdef HAVE__GETPTY"));

	slave = _getpty(ptyfd, O_RDWR, 0622, 0);
	if (slave == NULL) {
		TRACE(("pty_allocate error with GETPTY"));
		return 0;
	}
	strlcpy(namebuf, slave, namebuflen);
	/* Open the slave side. */
	*ttyfd = open(namebuf, O_RDWR | O_NOCTTY);
	if (*ttyfd < 0) {
		TRACE(("pty_allocate error: ttyftd open error"));
		close(*ptyfd);
		return 0;
	}
	return 1;
#else /* HAVE__GETPTY */
#if defined(HAVE_DEV_PTMX)
	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	int ptm;
	char *pts;
	mysig_t old_signal;

	TRACE(("#if defined(HAVE_DEV_PTMX)"));

	ptm = open("/dev/ptmx", O_RDWR | O_NOCTTY);
	if (ptm < 0) {
		TRACE(("/dev/ptmx: error"));
		/*error("/dev/ptmx: %.100s", strerror(errno)); matt */
		return 0;
	}
	old_signal = mysignal(SIGCHLD, SIG_DFL);
	if (grantpt(ptm) < 0) {
		TRACE(("grantpt: error"));
		/*error("grantpt: %.100s", strerror(errno)); matt */
		return 0;
	}
	mysignal(SIGCHLD, old_signal);
	if (unlockpt(ptm) < 0) {
		TRACE(("unlockpt: error"));
		/*error("unlockpt: %.100s", strerror(errno)); matt */
		return 0;
	}
	pts = ptsname(ptm);
	if (pts == NULL) {
		TRACE(("Slave pty side name cout not be obtained."));
		/* error("Slave pty side name could not be obtained."); matt */
	}
	strlcpy(namebuf, pts, namebuflen);
	*ptyfd = ptm;

	/* Open the slave side. */
	*ttyfd = open(namebuf, O_RDWR | O_NOCTTY);
	if (*ttyfd < 0) {
		TRACE(("error opening pts"));
/*		error("%.100s: %.100s", namebuf, strerror(errno)); matt */
		close(*ptyfd);
		return 0;
	}
#ifndef HAVE_CYGWIN
	/*
	 * Push the appropriate streams modules, as described in Solaris pts(7).
	 * HP-UX pts(7) doesn't have ttcompat module.
	 */
	if (ioctl(*ttyfd, I_PUSH, "ptem") < 0) {
		TRACE(("ioctl error 'ptem'"));
/*		error("ioctl I_PUSH ptem: %.100s", strerror(errno)); matt */
	}
	if (ioctl(*ttyfd, I_PUSH, "ldterm") < 0) {
		TRACE(("ioctl error 'ldterm'"));
/*		error("ioctl I_PUSH ldterm: %.100s", strerror(errno)); matt */
	}
#ifndef __hpux
	if (ioctl(*ttyfd, I_PUSH, "ttcompat") < 0) {
		TRACE(("ioctl error 'ttcompat'"));
/*		error("ioctl I_PUSH ttcompat: %.100s", strerror(errno)); matt */
	}
#endif
#endif
	return 1;
#else /* HAVE_DEV_PTMX */
#ifdef HAVE_DEV_PTS_AND_PTC
	/* AIX-style pty code. */
	const char *name;

	TRACE(("#ifdef HAVE_DEV_PTS_AND_PTC"));

	*ptyfd = open("/dev/ptc", O_RDWR | O_NOCTTY);
	if (*ptyfd < 0) {
		TRACE(("Could not open /dev/ptc"));
/*		error("Could not open /dev/ptc: %.100s", strerror(errno)); matt */
		return 0;
	}
	name = ttyname(*ptyfd);
	if (!name) {
		dropbear_exit("Open of /dev/ptc returns device for which ttyname fails.");
	}
	strlcpy(namebuf, name, namebuflen);
	*ttyfd = open(name, O_RDWR | O_NOCTTY);
	if (*ttyfd < 0) {
		TRACE(("Could not open pty slave side"));
/*		error("Could not open pty slave side %.100s: %.100s",
		    name, strerror(errno)); matt */
		close(*ptyfd);
		return 0;
	}
	return 1;
#else /* HAVE_DEV_PTS_AND_PTC */
#ifdef _UNICOS
	char buf[64];
	int i;
	int highpty;

#ifdef _SC_CRAY_NPTY
	highpty = sysconf(_SC_CRAY_NPTY);
	if (highpty == -1) {
		highpty = 128;
	}
#else
	highpty = 128;
#endif

	for (i = 0; i < highpty; i++) {
		snprintf(buf, sizeof(buf), "/dev/pty/%03d", i);
		*ptyfd = open(buf, O_RDWR|O_NOCTTY);
		if (*ptyfd < 0) {
			continue;
		}
		snprintf(namebuf, namebuflen, "/dev/ttyp%03d", i);
		/* Open the slave side. */
		*ttyfd = open(namebuf, O_RDWR|O_NOCTTY);
		if (*ttyfd < 0) {
			TRACE(("error opening slave side"));
/*			error("%.100s: %.100s", namebuf, strerror(errno)); matt */
			close(*ptyfd);
			return 0;
		}
		return 1;
	}
	return 0;
#else
	/* BSD-style pty code. */
	char buf[64];
	int i;
	const char *ptymajors = "pqrstuvwxyzabcdefghijklmnoABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const char *ptyminors = "0123456789abcdef";
	int num_minors = strlen(ptyminors);
	int num_ptys = strlen(ptymajors) * num_minors;
	struct termios tio;

	TRACE(("#else /* BSD-style pty code. */"));

	for (i = 0; i < num_ptys; i++) {
		snprintf(buf, sizeof buf, "/dev/pty%c%c", ptymajors[i / num_minors],
			 ptyminors[i % num_minors]);
		snprintf(namebuf, namebuflen, "/dev/tty%c%c",
		    ptymajors[i / num_minors], ptyminors[i % num_minors]);

		*ptyfd = open(buf, O_RDWR | O_NOCTTY);
		if (*ptyfd < 0) {
			/* Try SCO style naming */
			snprintf(buf, sizeof buf, "/dev/ptyp%d", i);
			snprintf(namebuf, namebuflen, "/dev/ttyp%d", i);
			*ptyfd = open(buf, O_RDWR | O_NOCTTY);
			if (*ptyfd < 0) {
				continue;
			}
		}

		/* Open the slave side. */
		*ttyfd = open(namebuf, O_RDWR | O_NOCTTY);
		if (*ttyfd < 0) {
			TRACE(("error opening slave side"));
/* 			error("%.100s: %.100s", namebuf, strerror(errno)); matt */
			close(*ptyfd);
			return 0;
		}
		/* set tty modes to a sane state for broken clients */
		if (tcgetattr(*ptyfd, &tio) < 0) {
			TRACE(("Getting tty modes for pty failed"));
/*			log("Getting tty modes for pty failed: %.100s", strerror(errno)); matt */
		} else {
			tio.c_lflag |= (ECHO | ISIG | ICANON);
			tio.c_oflag |= (OPOST | ONLCR);
			tio.c_iflag |= ICRNL;

			/* Set the new modes for the terminal. */
			if (tcsetattr(*ptyfd, TCSANOW, &tio) < 0) {
				TRACE(("Setting tty modes for pty failed"));
/*				log("Setting tty modes for pty failed: %.100s", strerror(errno)); matt */
			}
		}

		return 1;
	}
	return 0;
#endif /* CRAY */
#endif /* HAVE_DEV_PTS_AND_PTC */
#endif /* HAVE_DEV_PTMX */
#endif /* HAVE__GETPTY */
#endif /* HAVE_OPENPTY */
}

/* Releases the tty.  Its ownership is returned to root, and permissions to 0666. */

void
pty_release(const char *ttyname)
{
	if (chown(ttyname, (uid_t) 0, (gid_t) 0) < 0) {
		TRACE(("error release chowning tty"));
/*		error("chown %.100s 0 0 failed: %.100s", ttyname, strerror(errno)); matt */
	}
	if (chmod(ttyname, (mode_t) 0666) < 0) {
		TRACE(("error release chmodding tty"));
/*		error("chmod %.100s 0666 failed: %.100s", ttyname, strerror(errno)); matt */
	}
}

/* Makes the tty the processes controlling tty and sets it to sane modes. */

void
pty_make_controlling_tty(int *ttyfd, const char *ttyname)
{
	int fd;
#ifdef USE_VHANGUP
	void *old;
#endif /* USE_VHANGUP */

#ifdef _UNICOS
	if (setsid() < 0) {
		TRACE(("setsid error"));
/*		error("setsid: %.100s", strerror(errno)); matt */
	}

	fd = open(ttyname, O_RDWR|O_NOCTTY);
	if (fd != -1) {
		mysignal(SIGHUP, SIG_IGN);
		ioctl(fd, TCVHUP, (char *)NULL);
		mysignal(SIGHUP, SIG_DFL);
		setpgid(0, 0);
		close(fd);
	} else {
		TRACE(("Failed to disconnect from controlling tty."));
/* 		error("Failed to disconnect from controlling tty."); matt */
	}

	TRACE(("pty_make_controlling_tty: Setting controlling tty using TCSETCTTY."));
	ioctl(*ttyfd, TCSETCTTY, NULL);
	fd = open("/dev/tty", O_RDWR);
	if (fd < 0) {
		TRACE(("failed to open /dev/tty"));
/*		error("%.100s: %.100s", ttyname, strerror(errno)); matt */
	}
	close(*ttyfd);
	*ttyfd = fd;
#else /* _UNICOS */

	/* First disconnect from the old controlling tty. */
#ifdef TIOCNOTTY
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	if (fd >= 0) {
		(void) ioctl(fd, TIOCNOTTY, NULL);
		close(fd);
	}
#endif /* TIOCNOTTY */
	if (setsid() < 0) {
		TRACE(("setsid failed"));
/* 		error("setsid: %.100s", strerror(errno)); matt */
	}

	/*
	 * Verify that we are successfully disconnected from the controlling
	 * tty.
	 */
	fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
	if (fd >= 0) {
		TRACE(("pty_make_controlling_tty: Failed to disconnect from"
				" controlling tty.\n"));
		TRACE((stderr, "file is %s\n", _PATH_TTY));
		perror("ptymakething");
		close(fd);
	}
	/* Make it our controlling tty. */
#ifdef TIOCSCTTY
	TRACE(("pty_make_controlling_tty: Setting controlling tty using "
			"TIOCSCTTY.\n"));
	if (ioctl(*ttyfd, TIOCSCTTY, NULL) < 0) {
		TRACE(("ioctl(TIOCSCTTY) failed"));
		/*error("ioctl(TIOCSCTTY): %.100s", strerror(errno)); matt */
	}
#endif /* TIOCSCTTY */
#ifdef HAVE_NEWS4
	if (setpgrp(0,0) < 0) {
		TRACE(("SETPGRP failed"));
/*		error("SETPGRP %s",strerror(errno)); matt */
	}
#endif /* HAVE_NEWS4 */
#ifdef USE_VHANGUP
	old = mysignal(SIGHUP, SIG_IGN);
	vhangup();
	mysignal(SIGHUP, old);
#endif /* USE_VHANGUP */
	fd = open(ttyname, O_RDWR);
	if (fd < 0) {
		TRACE(("open ttyname failed"));
/*		error("%.100s: %.100s", ttyname, strerror(errno)); matt */
	} else {
#ifdef USE_VHANGUP
		close(*ttyfd);
		*ttyfd = fd;
#else /* USE_VHANGUP */
		close(fd);
#endif /* USE_VHANGUP */
	}
	/* Verify that we now have a controlling tty. */
	fd = open(_PATH_TTY, O_WRONLY);
	if (fd < 0) {
		TRACE(("pty_make_controlling_tty: failed to open /dev/tty"));
/*		error("open /dev/tty failed - could not set controlling tty: %.100s",
		    strerror(errno)); matt */
	} else {
		close(fd);
	}
#endif /* _UNICOS */
}

/* Changes the window size associated with the pty. */

void
pty_change_window_size(int ptyfd, int row, int col,
	int xpixel, int ypixel)
{
	struct winsize w;

	w.ws_row = row;
	w.ws_col = col;
	w.ws_xpixel = xpixel;
	w.ws_ypixel = ypixel;
	(void) ioctl(ptyfd, TIOCSWINSZ, &w);
}

void
pty_setowner(struct passwd *pw, const char *ttyname)
{
	struct group *grp;
	gid_t gid;
	mode_t mode;
	struct stat st;

	/* Determine the group to make the owner of the tty. */
	grp = getgrnam("tty");
	if (grp) {
		gid = grp->gr_gid;
		mode = S_IRUSR | S_IWUSR | S_IWGRP;
	} else {
		gid = pw->pw_gid;
		mode = S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH;
	}

	/*
	 * Change owner and mode of the tty as required.
	 * Warn but continue if filesystem is read-only and the uids match/
	 * tty is owned by root.
	 */
	if (stat(ttyname, &st)) {
		dropbear_exit("pty_setowner: stat failed");
/*		fatal("stat(%.101s) failed: %.100s", ttyname,
		    strerror(errno)); matt */
	}

	if (st.st_uid != pw->pw_uid || st.st_gid != gid) {
		if (chown(ttyname, pw->pw_uid, gid) < 0) {
			if (errno == EROFS &&
			    (st.st_uid == pw->pw_uid || st.st_uid == 0)) {
				TRACE(("pty_setowner: chown error"));
/*				error("chown(%.100s, %u, %u) failed: %.100s",
				    ttyname, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno));*/
			} else {
				dropbear_exit("pty_setowner: chown fatal");
/*				fatal("chown(%.100s, %u, %u) failed: %.100s",
				    ttyname, (u_int)pw->pw_uid, (u_int)gid,
				    strerror(errno)); matt */
			}
		}
	}

	if ((st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO)) != mode) {
		if (chmod(ttyname, mode) < 0) {
			if (errno == EROFS &&
			    (st.st_mode & (S_IRGRP | S_IROTH)) == 0) {
				TRACE(("chmod ttyname failed"));
/*				error("chmod(%.100s, 0%o) failed: %.100s",
				    ttyname, mode, strerror(errno)); matt*/
			} else {
				dropbear_exit("pty_setowner: chmod fatal");
/*				fatal("chmod(%.100s, 0%o) failed: %.100s",
				    ttyname, mode, strerror(errno)); matt */
			}
		}
	}
}
