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

#include "includes.h"
#include "buffer.h"
#include "dbutil.h"

int donerandinit = 0;

/* this is used to generate unique output from the same hashpool */
unsigned int counter = 0;
#define MAX_COUNTER 1000000/* the max value for the counter, so it won't loop */

unsigned char hashpool[SHA1_HASH_SIZE];

#define INIT_SEED_SIZE 32 /* 256 bits */

static void readrand(unsigned char* buf, unsigned int buflen);

/* The basic setup is we read some data from DEV_URANDOM or PRNGD and hash it
 * into hashpool. To read data, we hash together current hashpool contents,
 * and a counter. We feed more data in by hashing the current pool and new
 * data into the pool.
 *
 * It is important to ensure that counter doesn't wrap around before we
 * feed in new entropy.
 *
 */

static void readrand(unsigned char* buf, unsigned int buflen) {

	int readfd;
	unsigned int readpos, readlen;
#ifdef DROPBEAR_EGD
	struct sockaddr_un egdsock;
#endif

#ifdef DROPBEAR_DEV_URANDOM
	readfd = open(DEV_URANDOM, O_RDONLY);
	if (!readfd) {
		dropbear_exit("couldn't open random device");
	}
#endif

#ifdef DROPBEAR_EGD
	memset((void*)&egdsock, 0x0, sizeof(egdsock));
	egdsock.sun_family = AF_UNIX;
	strlcpy(egdsock.sun_path, DROPBEAR_EGD_SOCKET,
			sizeof(egdsock.sun_path));

	if ((readfd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		dropbear_exit("couldn't open random device");
	}
	/* todo - try various common locations */
	if (connect(readfd, (struct sockaddr*)&egdsock, 
			sizeof(struct sockaddr_un)) < 0) {
		dropbear_exit("couldn't open random device");
	}
#endif

	/* read the actual random data */
	readpos = 0;
	do {
		readlen = read(readfd, &buf[readpos], buflen - readpos);
		if (readlen <= 0) {
			if (readlen < 0 && errno == EINTR) {
				continue;
			}
			dropbear_exit("error reading random source");
		}
		readpos += readlen;
	} while (readpos < buflen);

	close (readfd);
}

/* initialise the prng from /dev/urandom or prngd */
void seedrandom() {
		
	unsigned char readbuf[INIT_SEED_SIZE];

	hash_state hs;

	/* initialise so compilers will be happy about hashing it */
	if (!donerandinit) {
		m_burn(hashpool, sizeof(hashpool));
	}

	/* get the seed data */
	readrand(readbuf, sizeof(readbuf));

	/* hash in the new seed data */
	sha1_init(&hs);
	sha1_process(&hs, (void*)hashpool, sizeof(hashpool));
	sha1_process(&hs, (void*)readbuf, sizeof(readbuf));
	sha1_done(&hs, hashpool);

	counter = 0;
	donerandinit = 1;
}

/* return len bytes of pseudo-random data */
void genrandom(unsigned char* buf, unsigned int len) {

	hash_state hs;
	unsigned char hash[SHA1_HASH_SIZE];
	unsigned int copylen;

	if (!donerandinit) {
		dropbear_exit("seedrandom not done");
	}

	while (len > 0) {
		sha1_init(&hs);
		sha1_process(&hs, (void*)hashpool, sizeof(hashpool));
		sha1_process(&hs, (void*)&counter, sizeof(counter));
		sha1_done(&hs, hash);

		counter++;
		if (counter > MAX_COUNTER) {
			seedrandom();
		}

		copylen = MIN(len, SHA1_HASH_SIZE);
		memcpy(buf, hash, copylen);
		len -= copylen;
		buf += copylen;
	}
	m_burn(hash, sizeof(hash));
}

/* Adds entropy to the PRNG state. As long as the hash is strong, then we
 * don't need to worry about entropy being added "diluting" the current
 * state - it should only make it stronger. */
void addrandom(unsigned char* buf, unsigned int len) {

	hash_state hs;
	if (!donerandinit) {
		dropbear_exit("seedrandom not done");
	}

	sha1_init(&hs);
	sha1_process(&hs, (void*)buf, len);
	sha1_process(&hs, (void*)hashpool, sizeof(hashpool));
	sha1_done(&hs, hashpool);
	counter = 0;

}
