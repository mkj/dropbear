/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * strlcat() is copyright as follows:
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include "includes.h"
#include "util.h"
#include "buffer.h"
#include "session.h"
#include "atomicio.h"

#define MAX_FMT 100

static void _dropbear_log(int priority, const char* format, va_list param);
static void _dropbear_exit(int exitcode, const char* format, va_list param);


#ifndef DISABLE_SYSLOG
int usingsyslog = 0; /* set by runopts, but required externally to sessions */
void startsyslog() {

	int fd;

	openlog(PROGNAME, LOG_PID, LOG_AUTHPRIV);

#ifndef DEBUG_TRACE
	/* redirect stdin/stdout/stderr to /dev/null */
	fd = open("/dev/null", O_RDWR);
	if (fd != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > 2) {
			close(fd);
		}
	}
#endif
	
}
#endif /* DISABLE_SYSLOG */

/* the "format" string must be <= 100 characters */
void dropbear_close(const char* format, ...) {

	va_list param;

	va_start(param, format);
	_dropbear_exit(EXIT_SUCCESS, format, param);
	va_end(param);

}

void dropbear_exit(const char* format, ...) {

	va_list param;

	va_start(param, format);
	_dropbear_exit(EXIT_FAILURE, format, param);
	va_end(param);
}

/* failure exit - format must be <= 100 chars */
static void _dropbear_exit(int exitcode, const char* format, va_list param) {

	char fmtbuf[200];

	if (!sessinitdone) {
		/* before session init */
		snprintf(fmtbuf, sizeof(fmtbuf), "exited: %s", format);
	} else if (ses.authstate.authdone) {
		/* user has authenticated */
		snprintf(fmtbuf, sizeof(fmtbuf),
				"exited after userauth (%s) from %s: %s", 
				ses.authstate.printableuser, ses.addrstring, format);
	} else {
		/* before userauth */
		snprintf(fmtbuf, sizeof(fmtbuf), "exited before userauth: %s",
				format);
	}

	_dropbear_log(LOG_INFO, fmtbuf, param);

	/* must be after using username etc */
	session_cleanup();

	exit(exitcode);

}

/* this is what can be called to write arbitrary log messages */
void dropbear_log(int priority, const char* format, ...) {

	va_list param;

	va_start(param, format);
	_dropbear_log(priority, format, param);
	va_end(param);
}

/* priority is priority as with syslog() */
static void _dropbear_log(int priority, const char* format, va_list param) {

	char printbuf[1024];
	char datestr[20];
	time_t timesec;

	vsnprintf(printbuf, sizeof(printbuf), format, param);

#ifndef DISABLE_SYSLOG
	if (usingsyslog) {
		syslog(priority, printbuf);
	} else 
#endif
	{
		timesec = time(NULL);
		if (strftime(datestr, sizeof(datestr), "%b %d %H:%M:%S", 
					localtime(&timesec)) == 0) {
			datestr[0] = '?'; datestr[1] = '\0';
		}
		fprintf(stderr, "%s %s\n", datestr, printbuf);
	}
}

#ifdef DEBUG_TRACE
void dropbear_trace(const char* format, ...) {

	va_list param;

	va_start(param, format);
	fprintf(stderr, "TRACE: ");
	vfprintf(stderr, format, param);
	fprintf(stderr, "\n");
	va_end(param);
}
#endif /* DEBUG_TRACE */

/* Return a string representation of the socket address passed. The return
 * value is allocated with strdup() */
unsigned char * getaddrstring(struct sockaddr * addr) {

	switch (addr->sa_family) {
		case PF_INET: 
			return strdup(inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
	}

	/* Need to extend for IP6 */
	return NULL;

}

/* Get the hostname corresponding to the address addr. On failure, the IP
 * address is returned. The return value is allocated with strdup() */
char* getaddrhostname(struct sockaddr * addr) {

	struct hostent *host = NULL;
	char * retstring;

#ifdef DO_HOST_LOOKUP
	host = gethostbyaddr((char*)&((struct sockaddr_in*)addr)->sin_addr,
			sizeof(struct in_addr), AF_INET);
#endif
	
	if (host == NULL) {
		/* return the address */
		retstring = inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
	} else {
		/* return the hostname */
		retstring = host->h_name;
	}

	return strdup(retstring);
}

#ifndef HAVE_STRLCPY
/* Implemented by matt as specified in freebsd 4.7 manpage.
 * We don't require great speed, is simply for use with sshpty code */
size_t strlcpy(char *dst, const char *src, size_t size) {

	size_t i;

	/* this is undefined, though size==0 -> return 0 */
	if (size < 1) {
		return 0;
	}

	for (i = 0; i < size-1; i++) {
		if (src[i] == '\0') {
			break;
		} else {
			dst[i] = src[i];
		}
	}

	dst[i] = '\0';
	return strlen(src);

}
#endif /* HAVE_STRLCPY */

#ifndef HAVE_STRNCAT
/* taken from openbsd-compat for OpenSSH 3.6.1p1 */
/* "$OpenBSD: strlcat.c,v 1.8 2001/05/13 15:40:15 deraadt Exp $"
 *
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t
strlcat(dst, src, siz)
	char *dst;
	const char *src;
	size_t siz;
{
	register char *d = dst;
	register const char *s = src;
	register size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}
#endif /* HAVE_STRLCAT */

#ifdef DEBUG_TRACE
void printhex(unsigned char* buf, int len) {

	int i;

	for (i = 0; i < len; i++) {
		fprintf(stderr, "%02x", buf[i]);
		if (i % 16 == 15) {
			fprintf(stderr, "\n");
		}
		else if (i % 2 == 1) {
			fprintf(stderr, " ");
		}
	}
	fprintf(stderr, "\n");
}
#endif

/* Strip all control characters from text (a null-terminated string), except
 * for '\n', '\r' and '\t'.
 * The result returned is a newly allocated string, this must be free()d after
 * use */
char * stripcontrol(const char * text) {

	char * ret;
	int len, pos;
	int i;
	
	len = strlen(text);
	ret = m_malloc(len+1);

	pos = 0;
	for (i = 0; i < len; i++) {
		if ((text[i] <= '~' && text[i] >= ' ') /* normal printable range */
				|| text[i] == '\n' || text[i] == '\r' || text[i] == '\t') {
			ret[pos] = text[i];
			pos++;
		}
	}
	ret[pos] = 0x0;
	return ret;
}
			



/* returns the current position on success, or -1 on failure */
int readln(int fd, char* buf, int count) {
	
	char in;
	int pos = 0;
	
	/* leave space to null-terminate */
	while (pos < count-1) {
		if (atomicio(read, fd, &in, 1) < 0) {
			break;
		}

		if (in == '\n' || in == '\r') {
			break;
		}

		buf[pos] = in;
		pos++;
	}
	buf[pos] = '\0';
	return pos;
}

/* reads the contents of filename into the buffer buf, from the current
 * position, either to the end of the file, or the buffer being full.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_readfile(buffer* buf, const char* filename) {

	int fd;
	int len;
	int maxlen;

	fd = open(filename, O_RDONLY);

	if (fd == -1) {
		close(fd);
		return DROPBEAR_FAILURE;
	}
	
	do {
		maxlen = buf->size - buf->pos;
		len = read(fd, buf_getwriteptr(buf, maxlen),
				maxlen);
		buf_incrwritepos(buf, len);
	} while (len != maxlen && len > 0);

	close(fd);
	return DROPBEAR_SUCCESS;
}

/* loop until the socket is closed (in case of EINTR) or
 * we get and error.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int m_close(int fd) {

	int val;
	do {
		val = close(fd);
	} while (val < 0 && errno == EINTR);

	if (val == 0 || errno == EBADF) {
		return DROPBEAR_SUCCESS;
	} else {
		return DROPBEAR_FAILURE;
	}
}
	
void * m_malloc(size_t size) {

	void* ret;

	if (size == 0) {
		dropbear_exit("m_malloc failed");
	}
	ret = malloc(size);
	if (ret == NULL) {
		dropbear_exit("m_malloc failed");
	}
	return ret;

}

void __m_free(void* ptr) {
	if (ptr != NULL) {
		free(ptr);
		ptr = NULL;
	}
}

void * m_realloc(void* ptr, size_t size) {

	void *ret;

	if (size == 0) {
		dropbear_exit("m_realloc failed");
	}
	ret = realloc(ptr, size);
	if (ret == NULL) {
		dropbear_exit("m_realloc failed");
	}
	return ret;
}

/* Clear the data, based on the method in David Wheeler's
 * "Secure Programming for Linux and Unix HOWTO" */
void m_burn(void *data, unsigned int len) {
	volatile char *p = data;

	if (data == NULL)
		return;
	while (len--) {
		*p++ = 0x66;
	}
}
