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
#include "dbutil.h"
#include "buffer.h"
#include "session.h"
#include "atomicio.h"

#define MAX_FMT 100

void (*_dropbear_exit)(int exitcode, const char* format, va_list param) = NULL;
void (*_dropbear_log)(int priority, const char* format, va_list param) = NULL;

int usingsyslog = 0; /* set by runopts, but required externally to sessions */
#ifndef DISABLE_SYSLOG
void startsyslog() {

	openlog(PROGNAME, LOG_PID, LOG_AUTHPRIV);

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


/* this is what can be called to write arbitrary log messages */
void dropbear_log(int priority, const char* format, ...) {

	va_list param;

	va_start(param, format);
	_dropbear_log(priority, format, param);
	va_end(param);
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

/* Connect via TCP to a host. Connection will try ipv4 or ipv6, will
 * return immediately if nonblocking is set */
int connect_remote(const char* remotehost, const char* remoteport,
		int nonblocking, char ** errstring) {

	struct addrinfo *res0 = NULL, *res = NULL, hints;
	int sock;
	int err;

	TRACE(("enter connect_remote"));

	if (errstring != NULL) {
		*errstring = NULL;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = PF_UNSPEC;

	err = getaddrinfo(remotehost, remoteport, &hints, &res0);
	if (err) {
		if (errstring != NULL && *errstring == NULL) {
			int len;
			len = 20 + strlen(gai_strerror(err));
			*errstring = (char*)m_malloc(len);
			snprintf(*errstring, len, "Error resolving: %s", gai_strerror(err));
		}
		TRACE(("Error resolving: %s", gai_strerror(err)));
		return -1;
	}

	sock = -1;
	err = EADDRNOTAVAIL;
	for (res = res0; res; res = res->ai_next) {

		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sock < 0) {
			err = errno;
			continue;
		}

		if (nonblocking) {
			if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
				close(sock);
				sock = -1;
				if (errstring != NULL && *errstring == NULL) {
					*errstring = m_strdup("Failed non-blocking");
				}
				TRACE(("Failed non-blocking: %s", strerror(errno)));
				continue;
			}
		}

		if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
			if (errno == EINPROGRESS) {
				TRACE(("Connect in progress"));
				break;
			} else {
				err = errno;
				close(sock);
				sock = -1;
				continue;
			}
		}

		break; /* Success */
	}

	if (sock < 0) {
		/* Failed */
		if (errstring != NULL && *errstring == NULL) {
			int len;
			len = 20 + strlen(strerror(err));
			*errstring = (char*)m_malloc(len);
			snprintf(*errstring, len, "Error connecting: %s", strerror(err));
		}
		TRACE(("Error connecting: %s", strerror(err)));
	} else {
		/* Success */
		/* (err is used as a dummy var here) */
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void*)&err, sizeof(err));
	}

	freeaddrinfo(res0);

	TRACE(("leave connect_remote: sock %d", sock));
	return sock;
}

/* Return a string representation of the socket address passed. The return
 * value is allocated with malloc() */
unsigned char * getaddrstring(struct sockaddr * addr) {

	char *retstring;

	/* space for "255.255.255.255:65535\0" = 22 */
	retstring = m_malloc(22);

	switch (addr->sa_family) {
		case PF_INET: 
			snprintf(retstring, 22, "%s:%hu",
					inet_ntoa(((struct sockaddr_in *)addr)->sin_addr),
					((struct sockaddr_in *)addr)->sin_port);
			break;

		default:
			/* XXX ipv6 */
			strcpy(retstring, "Bad protocol");

	}
	return retstring;

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

	return m_strdup(retstring);
}
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
			

/* reads the contents of filename into the buffer buf, from the current
 * position, either to the end of the file, or the buffer being full.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_readfile(buffer* buf, const char* filename) {

	int fd;
	int len;
	int maxlen;

	fd = open(filename, O_RDONLY);

	if (fd < 0) {
		close(fd);
		return DROPBEAR_FAILURE;
	}
	
	do {
		maxlen = buf->size - buf->pos;
		len = read(fd, buf_getwriteptr(buf, maxlen),
				maxlen);
		buf_incrwritepos(buf, len);
	} while (len < maxlen && len > 0);

	close(fd);
	return DROPBEAR_SUCCESS;
}

/* get a line from the file into buffer in the style expected for an
 * authkeys file.
 * Will return DROPBEAR_SUCCESS if data is read, or DROPBEAR_FAILURE on EOF.*/
/* Only used for ~/.ssh/known_hosts and ~/.ssh/authorized_keys */
#if defined(DROPBEAR_CLIENT) || defined(DROPBEAR_PUBKEY_AUTH)
int buf_getline(buffer * line, FILE * authfile) {

	int c = EOF;

	TRACE(("enter buf_getline"));

	buf_setpos(line, 0);
	buf_setlen(line, 0);

	while (line->pos < line->size) {

		c = fgetc(authfile); /*getc() is weird with some uClibc systems*/
		if (c == EOF || c == '\n' || c == '\r') {
			goto out;
		}

		buf_putbyte(line, (unsigned char)c);
	}

	TRACE(("leave getauthline: line too long"));
	/* We return success, but the line length will be zeroed - ie we just
	 * ignore that line */
	buf_setlen(line, 0);

out:

	buf_setpos(line, 0);

	/* if we didn't read anything before EOF or error, exit */
	if (c == EOF && line->pos == 0) {
		TRACE(("leave getauthline: failure"));
		return DROPBEAR_FAILURE;
	} else {
		TRACE(("leave getauthline: success"));
		return DROPBEAR_SUCCESS;
	}

	TRACE(("leave buf_getline"));
}	
#endif

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

void * m_strdup(const char * str) {
	char* ret;

	ret = strdup(str);
	if (ret == NULL) {
		dropbear_exit("m_strdup failed");
	}
	return ret;
}

void __m_free(void* ptr) {
	if (ptr != NULL) {
		free(ptr);
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

