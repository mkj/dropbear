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
 * SOFTWARE. */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>

#include "options.h"
#include "util.h"
#include "buffer.h"
#include "session.h"
#include "libtomcrypt/mycrypt.h"

#define MAX_FMT 100

static void _dropbear_log(int priority, const char* format, va_list param);
static void _dropbear_exit(int exitcode, const char* format, va_list param);

int usingsyslog = 0;

void startsyslog() {

	int fd;

	openlog(PROGNAME, LOG_PID, LOG_DAEMON);

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
	
	usingsyslog = 1;
}

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

#define EXIT_MESSAGE "exited: "
#define EXIT_MESSAGE_LEN 8

	char fmtbuf[MAX_FMT+EXIT_MESSAGE_LEN+1];

#ifdef DOCLEANUP
	session_cleanup();
#endif

	strcpy(fmtbuf, EXIT_MESSAGE);
	strncat(fmtbuf, format, MAX_FMT);

	_dropbear_log(LOG_DAEMON | LOG_INFO, fmtbuf, param);

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

	if (usingsyslog) {
		vsyslog(priority, format, param);
	} else {
		fprintf(stderr, "dropbear ");
		vfprintf(stderr, format, param);
		fprintf(stderr, "\n");
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

/* returns the current position on success, or -1 on failure */
int readln(int fd, char* buf, int count) {
	
	char in;
	int pos;
	int num;
	fd_set fds;
	struct timeval timeout;
	
	FD_ZERO(&fds);


	pos = 0;
	/* hack so we can block on a non-blocking fd */
	for (;;) {
		if (pos >= count-1) {
			break;
		}
		FD_SET(fd, &fds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		if (select(fd+1, &fds, NULL, NULL, &timeout) < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (FD_ISSET(fd, &fds)) {
			num = read(fd, &in, 1);
			if (num <= 0 || '\n' == in) {
				break;
			}
			if (in != '\r') {
				buf[pos] = in;
				pos++;
			}
		}
	}
	buf[pos] = '\0';
	
	return pos;
	
}

/* Atomically write a string to a non-blocking socket.
 * Returns 0 on success, -1 on failure */
int writeln(int fd, char* str) {

	int len, writelen, pos = 0;
	fd_set fds;
	struct timeval timeout;

	len = strlen(str);
	
	FD_ZERO(&fds);

	for (;;) {
		FD_SET(fd, &fds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		if (select(fd+1, NULL, &fds, NULL, &timeout) < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		if (FD_ISSET(fd, &fds)) {
			writelen = write(fd, &str[pos], len - pos);
			if (writelen < 0) {
				if (errno == EINTR) {
					continue;
				}
				return -1;
			}
			pos += writelen;
		}
		if (pos >= len) {
			break;
		}
	}
	return 0;
}


/* reads the contents of filename into the buffer buf, from the current
 * position, either to the end of the file, or the buffer being full.
 * Returns 0 on success, -1 on failure */
int buf_readfile(buffer* buf, char* filename) {

	int fd;
	int len;
	int maxlen;

	fd = open(filename, O_RDONLY);

	if (fd == -1) {
		close(fd);
		return -1;
	}
	
	do {
		maxlen = buf->size - buf->pos;
		len = read(fd, buf_getwriteptr(buf, maxlen),
				maxlen);
		buf_incrwritepos(buf, len);
	} while (len != maxlen && len > 0);

	close(fd);
	return 0;
}

/* loop until the socket is closed (in case of EINTR) or
 * we get and error.
 * Returns 0 on fd successfully closed or bad FD, -1 otherwise */
int m_close(int fd) {

	int val;
	do {
		val = close(fd);
	} while (val < 0 && errno == EINTR);
	return (val == -1 &&
			errno == EBADF) ? 0 : val;
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
