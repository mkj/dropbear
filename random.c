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

int donerandinit = 0;

prng_state prng;

#define ENTROPY_ADD_AMOUNT 200
#define MAX_ENTROPY_ADD 2000 /* basically to stop overflow of the counter */
#define INIT_SEED_SIZE 32 /* 256 bits */

/* we reseed after addcount reaches ENTROPY_ADD_AMOUNT, though we also include
 * the previous state to avoid someone flushing the state to something known */
unsigned int addcount = 0;

/* The basic approach of the PRNG is to start with an initial good random
 * source (such as /dev/random on supported systems), then feed in further
 * entropy from timings etc. This is all hashed with libtomcrypt's yarrow
 * implementation, which should ensure that as as long as there is some initial
 * random data, it will not be possible to calculate further states, or force
 * the generator into a known state - at least not without guessing the initial
 * state or breaking the hash function */

/* Will read in randomness from /dev/random or EGD, and initialise the yarrow
 * state */
void initrandom() {
		
	unsigned char randbuf[INIT_SEED_SIZE];
	int randfd;
	int readlen, readpos;
#ifdef DROPBEAR_EGD
	struct sockaddr_un egdsock;
#endif

	/* clear the state if it has already been started */
	m_burn(&prng, sizeof(prng));
	addcount = 0;

#ifdef DROPBEAR_DEV_RANDOM
	randfd = open(DEV_RANDOM, O_RDONLY);
	if (!randfd) {
		dropbear_exit("couldn't open random device");
	}
#endif

#ifdef DROPBEAR_EGD
	egdsock.sun_family = AF_UNIX;
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
#endif

	if (yarrow_start(&prng) != CRYPT_OK) {
		dropbear_exit("error in yarrow PRNG");
	}

	
	/* read the actual random data */
	readpos = 0;
	do {
		readlen = read(randfd, &randbuf[readpos], sizeof(randbuf) - readpos);
		if (readlen <= 0) {
			if (errno == EINTR) {
				continue;
			}
			dropbear_exit("error reading random source");
		}
		readpos += readlen;
	} while (readpos < sizeof(randbuf));

	close (randfd);

	if (yarrow_add_entropy(randbuf, sizeof(randbuf), &prng) != CRYPT_OK) {
		dropbear_exit("error in yarrow PRNG");
	}
	m_burn(randbuf, sizeof(randbuf));
	

	if (yarrow_ready(&prng) != CRYPT_OK) {
		dropbear_exit("error in yarrow PRNG");
	}

	donerandinit = 1;

}

void genrandom(unsigned char* buf, int len) {

	assert(donerandinit);

	/* XXX m_burn is required since yarrow_read relies on the contents of
	 * buf for its prng. This isn't a problem in itself, but memory
	 * debuggers like Valgrind don't like the undefined memory being used */
	m_burn(buf, len);
	if (yarrow_read(buf, len, &prng) != len) {
		dropbear_exit("error in yarrow PRNG");
	}
	
}

/* Adds entropy to the PRNG state. As long as the hash is strong, then we
 * don't need to worry about entropy being added "diluting" the current
 * state - it should only make it stronger. After every ENTROPY_ADD_AMOUNT we
 * reseed. Reseeding also includes the previous state, so we can't get forced
 * to use just the new stuff */
void addrandom(unsigned char* buf, int len) {

	assert(donerandinit);

	if (len > MAX_ENTROPY_ADD) {
		dropbear_exit("error in yarrow PRNG");
	}

	if (yarrow_add_entropy(buf, len, &prng) != CRYPT_OK) {
		dropbear_exit("error in yarrow PRNG");
	}
	addcount += len;
	
	if (addcount >= ENTROPY_ADD_AMOUNT) {
		if (yarrow_ready(&prng) != CRYPT_OK) {
			dropbear_exit("error in yarrow PRNG");
		}
		addcount = 0;
	}
}
