#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "options.h"
#include "util.h"
#include "bignum.h"
#include "random.h"
#include "rsa.h"
#include "genrsa.h"

#include "libtomcrypt/mpi.h"
#include "libtomcrypt/mycrypt.h"

#define RSA_E 65537

#define KEYSIZE 1024/8

static void getrsaprime(mp_int* prime, mp_int *primeminus, 
		mp_int* rsa_e, unsigned int size, int wprng);

int main(int argc, char ** argv) {

	rsa_key *key;
	buffer *buf;
	int fd;
	int ret;
	
	if (argc != 2) {
		printf("usage: genrsa rsaprivkeyfile\n");
		exit(0);
	}
	
	printf("starting generation\n");
	key = gen_rsa_priv_key(KEYSIZE);
	printf("done generation\n");
	printf("n size = %d bits %d bytes\n", mp_count_bits(key->n),
			mp_unsigned_bin_size(key->n));

	buf = buf_new(3000);
	buf_put_rsa_priv_key(buf, key);
	TRACE(("after buf_put_rsa_priv_key"));
	/* write it */
	fd = open(argv[1], O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	buf_setpos(buf, 0);
	ret = write(fd, buf_getptr(buf, buf->len), buf->len);
	if (ret != buf->len) {
		fprintf(stderr, "error writing to file, short write %d\n",
				ret);
	}

	close(fd);

	buf_free(buf);

	rsa_key_free(key);
	return 0;
	
}
/* mostly taken from libtomcrypt's rsa key generation routine */
rsa_key * gen_rsa_priv_key(unsigned int size) {

	rsa_key * key;
	mp_int p, pminus, q, qminus, lcm;
	int wprng;
	char out[1000];

	key = (rsa_key*)m_malloc(sizeof(rsa_key));

	key->e = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(key->e);
	key->n = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(key->n);
	key->d = (mp_int*)m_malloc(sizeof(mp_int));
	m_mp_init(key->d);

	if (mp_set_int(key->e, RSA_E) != MP_OKAY) {
		fprintf(stderr, "rsa generation failed\n");
		exit(1);
	}

	wprng = register_prng(&sprng_desc);
	if (wprng == -1) {
		fprintf(stderr, "rsa generation failed\n");
		exit(1);
	}
	initrandom();
	
	m_mp_init(&pminus);
	m_mp_init(&p);
	getrsaprime(&p, &pminus, key->e, size/2, wprng);
	m_mp_init(&qminus);
	m_mp_init(&q);
	getrsaprime(&q, &qminus, key->e, size/2, wprng);

	if (mp_mul(&p, &q, key->n) != MP_OKAY) {
		fprintf(stderr, "rsa generation failed\n");
		exit(1);
	}

	fprintf(stderr, "bits: p %d q  %d n %d\n",
			mp_count_bits(&p), mp_count_bits(&q), mp_count_bits(key->n));

	m_mp_init(&lcm);
	if (mp_lcm(&pminus, &qminus, &lcm) != MP_OKAY) {
		fprintf(stderr, "rsa generation failed\n");
		exit(1);
	}

	if (mp_invmod(key->e, &lcm, key->d) != MP_OKAY) {
		fprintf(stderr, "rsa generation failed\n");
		exit(1);
	}

	mp_toradix(key->e, out, 10);
	fprintf(stderr, "key->e sign %d\n%s\n", SIGN(key->e), out);
	mp_toradix(key->d, out, 10);
	fprintf(stderr, "key->d sign %d\n%s\n", SIGN(key->d), out);
	mp_toradix(key->n, out, 10);
	fprintf(stderr, "key->n sign %d\n%s\n", SIGN(key->n), out);

	mp_clear(&pminus);
	mp_clear(&qminus);
	mp_clear(&lcm);

	return key;

}	

/* return a prime suitable for p or q */
static void getrsaprime(mp_int* prime, mp_int *primeminus, 
		mp_int* rsa_e, unsigned int size, int wprng) {

	int isprime;
	unsigned char *buf;
	mp_int temp_gcd;

	m_mp_init(&temp_gcd);
	buf = (unsigned char*)m_malloc(size+1);
	printf("getprimesubone here\n");
	do {
#if 0
		/* generate a prime */
		if (rand_prime(prime, size, NULL, wprng) != CRYPT_OK) {
			fprintf(stderr, "rsa generation failed\n");
			exit(1);
		}
#else 
		isprime = 0;
		do {
			genhighrandom(buf, size);
			buf[0] |= 0x80; /* MSB set */
			buf[size] |= 0x01; /* LSB for odd */

			if (mp_read_unsigned_bin(prime, buf, size) != MP_OKAY) {
				fprintf(stderr, "rsa generation failed\n");
				exit(1);
			}

			/* check is prime */
			if (is_prime(prime, &isprime) != CRYPT_OK) {
				fprintf(stderr, "rsa generation failed\n");
				exit(1);
			}

		} while (!isprime);
		printhex(buf, 10);
#endif
		printf("have prime here\n");

		/* subtract one */
		if (mp_sub_d(prime, 1, primeminus) != MP_OKAY) {
			fprintf(stderr, "rsa generation failed\n");
			exit(1);
		}
		/* check relative primality */
		if (mp_gcd(primeminus, rsa_e, &temp_gcd) != MP_OKAY) {
			fprintf(stderr, "rsa generation failed\n");
			exit(1);
		}
	} while (mp_cmp_d(&temp_gcd, 1) != 0); /* while gcd(p-1, e) != 1 */

	/* now we have a good value for result */
	mp_clear(&temp_gcd);
	m_free(buf);
	
}
