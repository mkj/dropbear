#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>

#include "options.h"
#include "util.h"
#include "buffer.h"
#include "session.h"
#include "libtomcrypt/mycrypt.h"

/* abort() on detected heap corruption */
#define MALLOC_CHECK_ 2

void dropbear_msg(const char* format, ...) {

	va_list param;

	va_start(param, format);
	fprintf(stderr, "dropbear: ");
	vfprintf(stderr, format, param);
	fprintf(stderr, "\n");
	va_end(param);

}
void dropbear_close(const char* format, ...) {

	va_list param;

#ifdef DOCLEANUP
	session_cleanup();
#endif

	va_start(param, format);
	fprintf(stderr, "dropbear close: ");
	vfprintf(stderr, format, param);
	fprintf(stderr, "\n");
	va_end(param);
	exit(EXIT_SUCCESS);

}

/* failure exit */
void dropbear_exit(const char* format, ...) {

	va_list param;

#ifdef DOCLEANUP
	session_cleanup();
#endif

	va_start(param, format);
	fprintf(stderr, "dropbear exit: ");
	vfprintf(stderr, format, param);
	fprintf(stderr, "\n");
	va_end(param);
	exit(EXIT_FAILURE);

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
	/* XXX hack for non-blocking*/
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
	
void * m_malloc(size_t size) {

	return m_realloc(NULL, size);

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
		*p++ = '\0';
	}
}
