#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "options.h"
#include "util.h"
#include "signkey.h"
#include "bignum.h"
#include "random.h"
#include "buffer.h"
#include "libtomcrypt/mpi.h"
#include "libtomcrypt/mycrypt.h"

/* random number generator */

#define PSIZE 128 /* 1024 bit*/
#define QSIZE 20 /* 160 bit */

static void getq(dss_key *key);
static void getp(dss_key *key);
static void getg(dss_key *key);
static void getx(dss_key *key);
static void gety(dss_key *key);

int main(int argc, char ** argv) {

	dss_key key;
	buffer *buf;
	int fd;
	int ret;
	
	if (argc != 2) {
		printf("usage: genkey dssprivkeyfile\n");
		exit(0);
	}
	
	key.p = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(key.p);
	key.q = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(key.q);
	key.g = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(key.g);
	key.y = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(key.y);
	key.x = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(key.x);
	
	initrandom();
	
	getq(&key);
	getp(&key);
	getg(&key);
	getx(&key);
	gety(&key);
	printf("done it all\n");

	buf = buf_new(3000);
	printf("past the new\n");
	buf_put_dss_priv_key(buf, &key);
	printf("past the new2\n");
	/* write it */
	fd = open(argv[1], O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	buf_setpos(buf, 0);
	printf("past setpos\n");
	ret = write(fd, buf_getptr(buf, buf->len), buf->len);
	if (ret != buf->len) {
		fprintf(stderr, "error writing to file, short write %d\n",
				ret);
	}

	close(fd);

	buf_free(buf);

	mp_clear(key.p);
	mp_clear(key.q);
	mp_clear(key.g);
	mp_clear(key.y);
	mp_clear(key.x);
	m_free(key.p);
	m_free(key.q);
	m_free(key.g);
	m_free(key.y);
	m_free(key.x);

	
	
	return 0;
	
}

static void getq(dss_key *key) {

	int result;
	char buf[QSIZE];

	/* 160 bit prime */
	result = 0;
	do {
		genrandom(buf, QSIZE);
		buf[0] |= 0x01; /* bottom bit low */
		buf[QSIZE-1] |= 0x80; /* top bit high */

		if (mp_read_unsigned_bin(key->q, buf, QSIZE) != MP_OKAY) {
			fprintf(stderr, "error creating rand q\n");
			exit(1);
		}

		/* check for prime */
		if (is_prime(key->q, &result) != CRYPT_OK) {
			fprintf(stderr, "error checking primality of q");
			exit(1);
		}

	} while (!result);

	printf("q is made\n");

}

static void getp(dss_key *key) {

	mp_int tempX, tempC, tempP, temp2q;
	int result;
	char buf[PSIZE];
	int count;


	m_mp_init(&tempX);
	m_mp_init(&tempC);
	m_mp_init(&tempP);
	m_mp_init(&temp2q);


	/* 2*q */
	if (mp_mul_d(key->q, 2, &temp2q) != MP_OKAY) {
		fprintf(stderr, "Couldn't mul*2 q\n");
		exit(1);
	}

	result = 0;
	count = 0;
	do {
		
		genrandom(buf, PSIZE);
		buf[0] |= 0x01; /* set the bottom bit low */
		buf[PSIZE-1] |= 0x80; /*set top bit high */

		/* X is a random mp_int */
		if (mp_read_unsigned_bin(&tempX, buf, PSIZE) != MP_OKAY) {
			fprintf(stderr, "error creating temp mpint\n");
			exit(1);
		}

		/* C = X mod 2q */
		if (mp_mod(&tempX, &temp2q, &tempC) != MP_OKAY) {
			fprintf(stderr, "error modulo\n");
			exit(1);
		}

		/* P = X - (C - 1) = X - C + 1*/
		if (mp_sub(&tempX, &tempC, &tempP) != MP_OKAY) {
			fprintf(stderr, "error sub\n");
			exit(1);
		}
		
		if (mp_add_d(&tempP, 1, key->p) != MP_OKAY) {
			fprintf(stderr, "error add 1\n");
			exit(1);
		}

		/* now check for prime */
		/* result == 1  =>  p is prime */
		if (is_prime(key->p, &result) != CRYPT_OK) {
			fprintf(stderr, "error checking primality of p");
			exit(1);
		}
		count++;
	} while (!result);

	printf("done doing making p, count = %d\n", count);

	mp_clear(&tempX);
	mp_clear(&tempC);
	mp_clear(&temp2q);
	mp_clear(&tempP);
}

static void getg(dss_key * key) {

	char printbuf[1000];
	mp_int div, h, val, dummy;

	m_mp_init(&div);
	m_mp_init(&h);
	m_mp_init(&val);
	m_mp_init(&dummy);

	/* get (p-1)/q */
	if (mp_sub_d(key->p, 1, &val) != MP_OKAY) {
		fprintf(stderr, "not working\n");
		exit(1);
	}
	if (mp_div(&val, key->q, &div, &dummy) != MP_OKAY) {
		fprintf(stderr, "can't div\n");
		exit(1);
	}

	/* initialise h=1 */
	mp_set(&h, 1);

	do {
		/* now keep going with g=h^div mod p, until g > 1 */
		if (mp_exptmod(&h, &div, key->p, key->g) != MP_OKAY) {
			fprintf(stderr, "g not calcing\n");
			exit(1);
		}

		if (mp_add_d(&h, 1, &dummy) != MP_OKAY) {
			fprintf(stderr, "h not incrementing\n");
			exit(1);
		}
		mp_exch(&h, &dummy);
	
	} while (mp_cmp_d(key->g, 1) <= 0);

	printf("got g:\n");
	mp_toradix(key->g, printbuf, 10);
	printf("%s\n", printbuf);

	mp_clear(&div);
	mp_clear(&h);
	mp_clear(&val);
	mp_clear(&dummy);
}

static void getx(dss_key *key) {

	mp_int val;
	char buf[QSIZE];
	
	m_mp_init(&val);
	
	do {
		genrandom(buf, QSIZE);

		if (mp_read_unsigned_bin(&val, buf, QSIZE) != MP_OKAY) {
			fprintf(stderr, "couldn't load random num\n");
		}
	} while ((mp_cmp_d(&val, 1) > 1) && (mp_cmp(&val, key->q) < 1));

	mp_copy(&val, key->x);
	mp_clear(&val);

}

static void gety(dss_key *key) {

 if (mp_exptmod(key->g, key->x, key->p, key->y) != MP_OKAY) {
	 fprintf(stderr, "couldn't gen y\n");
	 exit(1);
 }
}
