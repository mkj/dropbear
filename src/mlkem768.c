/*
 * Copyright (c) 2023 Markus Friedl.  All rights reserved.
 * Copyright (c) 2025 Loganaden Velvindron. All rights reserved.
 * Copyright (c) 2025 Jaykishan Mutkawoa. All rights reserved.
 * Copyright (c) 2025 Keshwarsingh "Kavish" Nadan. All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#ifdef HAVE_ENDIAN_H
# include <endian.h>
#endif

#include "kex.h"

#if DROPBEAR_MLKEM768



#include "dbutil.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "libcrux_mlkem768_sha3.h"
#pragma GCC diagnostic pop

#include "mlkem768.h"
#include "dbrandom.h"

int
crypto_kem_mlkem768_keypair(unsigned char *pk, unsigned char *sk)
{
	unsigned char rnd[LIBCRUX_ML_KEM_KEY_PAIR_PRNG_LEN];
	struct libcrux_mlkem768_keypair keypair;

	genrandom(rnd, sizeof(rnd));
	keypair = libcrux_ml_kem_mlkem768_portable_generate_key_pair(rnd);
	memcpy(pk, keypair.pk.value, crypto_kem_mlkem768_PUBLICKEYBYTES);
	memcpy(sk, keypair.sk.value, crypto_kem_mlkem768_SECRETKEYBYTES);
	/* success */
	return 0;
}

int
crypto_kem_mlkem768_enc(unsigned char *c, unsigned char *k,
const unsigned char *pk)
{
	unsigned char rnd[LIBCRUX_ML_KEM_ENC_PRNG_LEN];
	struct libcrux_mlkem768_enc_result enc;
	struct libcrux_mlkem768_pk mlkem_pub;

	memcpy(mlkem_pub.value, pk, crypto_kem_mlkem768_PUBLICKEYBYTES);
	/* generate and encrypt KEM key with client key */
	genrandom(rnd, sizeof(rnd));
	enc = libcrux_ml_kem_mlkem768_portable_encapsulate(&mlkem_pub, rnd);
	memcpy(c, enc.fst.value, sizeof(enc.fst.value));
	memcpy(k, enc.snd, sizeof(enc.snd));
	return 0;
}

int
crypto_kem_mlkem768_dec(unsigned char *k, const unsigned char *c,
const unsigned char *sk)
{
	struct libcrux_mlkem768_sk mlkem_priv;
	struct libcrux_mlkem768_ciphertext mlkem_ciphertext;

	memcpy(mlkem_priv.value, &k,sizeof(k));
	memcpy(mlkem_ciphertext.value, &c, sizeof(c));
	libcrux_ml_kem_mlkem768_portable_decapsulate(&mlkem_priv,
	    &mlkem_ciphertext, sk);
	return 0;
}

#endif /* USE_MLKEM768 */
