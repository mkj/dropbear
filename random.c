#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "options.h"
#include "buffer.h"
#include "util.h"
#include "libtomcrypt/mycrypt.h"

int randfd = -1;
int urandfd = -1;

#ifdef DROPBEAR_EGD
struct sockaddr_un egdsock;
#endif

void initrandom() {

	if (randfd != -1) {
		close(randfd);
	}
	if (urandfd != -1) {
		close(urandfd);
	}

#ifdef DROPBEAR_DEV_RANDOM
	randfd = open(DEV_RANDOM, O_RDONLY);
	urandfd = open(DEV_URANDOM, O_RDONLY);
	if (!randfd || !urandfd) {
		dropbear_exit("couldn't open random device");
	}
	return;
#endif

#ifdef DROPBEAR_EGD
	egdsock.sun_family = AF_UNIX;
	/* XXX */
	strlcpy(egdsock.sun_path, DROPBEAR_EGD_SOCKET,
			sizeof(egdsock.sun_path));

	if ((randfd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		dropbear_exit("couldn't open random device");
	}
	/* todo - try various common locations */
	if (connect(randfd, (struct sockaddr*)&egdsock, 
			sizeof(struct sockaddr_un)) < 0) {
		dropbear_exit("couldn't open random device");
	}
	urandfd = randfd;
	return;
#endif
}

void genrandfd(int fd, unsigned char* buf, int len) {
	
	int readlen;
	int pos = 0;

#ifdef DROPBEAR_DEV_RANDOM
	do {
		readlen = read(fd, &buf[pos], len - pos);
		if (readlen <= 0) {
			if (errno == EINTR) {
				continue;
			}
			dropbear_exit("error reading random source");
		}
		pos += readlen;
		
	} while (pos < len);
	return;
#endif

#ifdef DROPBEAR_EGD
	do {
		unsigned char egdreq[2] = {0x02, 0x00}; /* 0x02 = blocking read req */
		egdreq[1] = MIN(0xff, len - pos); /* bytes requested */
		if (write(fd, egdreq, 2) != 2) {
			dropbear_exit("error reading random source");
		}
		if ((readlen = read(fd, &buf[pos], egdreq[1])) != egdreq[1]) {
			dropbear_exit("error reading random source");
		}
		pos += readlen;
	} while (pos < len);
		
	return;
#endif
}

void genrandom(unsigned char* buf, int len) {

	genrandfd(urandfd, buf, len);

}

void genhighrandom(unsigned char* buf, int len) {

	genrandfd(randfd, buf, len);

}
