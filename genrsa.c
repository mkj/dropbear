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

#include "libtomcrypt/mycrypt.h"

#define RSA_E 65537

#define KEYSIZE 1024/8

#ifdef DROPBEAR_RSA

static void getrsaprime(mp_int* prime, mp_int *primeminus, 
		mp_int* rsa_e, unsigned int size, int wprng);

/* mostly taken from libtomcrypt's rsa key generation routine */
rsa_key * gen_rsa_priv_key(unsigned int size) {

	rsa_key * key;
	mp_int p, pminus, q, qminus, lcm;
	int wprng;

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

	initrandom();

	/* XXX this relies on initrandom for entropy etc */
	wprng = register_prng(&yarrow_desc);
	if (wprng == -1) {
		fprintf(stderr, "rsa generation failed\n");
		exit(1);
	}
	
	m_mp_init(&pminus);
	m_mp_init(&p);
	m_mp_init(&qminus);
	m_mp_init(&q);

	/* putty doesn't like it if the modulus isn't a multiple of 8 bits,
	 * so we just generate them until we get one which is OK */
	do {
		getrsaprime(&p, &pminus, key->e, size/2, wprng);
		getrsaprime(&q, &qminus, key->e, size/2, wprng);

		if (mp_mul(&p, &q, key->n) != MP_OKAY) {
			fprintf(stderr, "rsa generation failed\n");
			exit(1);
		}
	} while (mp_count_bits(key->n) % 8 != 0);

	m_mp_init(&lcm);
	if (mp_lcm(&pminus, &qminus, &lcm) != MP_OKAY) {
		fprintf(stderr, "rsa generation failed\n");
		exit(1);
	}

	if (mp_invmod(key->e, &lcm, key->d) != MP_OKAY) {
		fprintf(stderr, "rsa generation failed\n");
		exit(1);
	}

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
	do {
#if 0 /* currently rand_prime way is broken, use the other */
		/* generate a prime with libtomcrypt */
		if (rand_prime(prime, size, NULL, wprng) != CRYPT_OK) {
			fprintf(stderr, "rsa generation failed\n");
			exit(1);
		}
#else 
		/* generate a prime by getting a random number and checking
		 * for primality - inefficient but works */
		isprime = 0;
		do {
			genrandom(buf, size);
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
#endif

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

#endif /* DROPBEAR_RSA */
