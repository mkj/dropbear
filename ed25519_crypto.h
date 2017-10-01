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

#ifndef DROPBEAR_ED25519_CRYPTO_H_
#define DROPBEAR_ED25519_CRYPTO_H_

#include "includes.h"
#include "buffer.h"

#ifdef DROPBEAR_ED25519

/* This API is based on the NaCl and TweetNaCl APIs, but it is not
 * compatible with them.
 */

/* Generates a public verification key from a private ed25519 signing key.
 *
 * Input: private signing key is sk[:32]. It can be any random 32 bytes.
 * Output: public verification key is pk[:32].
 */
void ed25519_crypto_getpublic(uint8_t *pk, const uint8_t *sk);

/* Signs a message using ed25119.
 *
 * Input: message is m[:n].
 * Input: private key is sk[:32].
 * Input: public key is sk[32 : 64]. If not available, generate it from
 *        the private key using ed25519_crypto_getpublic.
 * Output: signature is sm[:64].
 * Output: copy of message is sm[64 : 64 + n].
 */
void ed25519_crypto_sign(uint8_t *sm, const uint8_t *m, uint32_t n,
                         const uint8_t *sk);

/* Verifies a signed ed25119 message.
 *
 * Input: signature is sm[:64].
 * Input: message is sm[64 : 64 + n].
 * Input: public key is pk[:32].
 * Output: success (i.e. good signature) is indicated by returning 0.
 * Output: as a side effect, overwrites (with any bytes) sm[32 : 64].
 */
int ed25519_crypto_verify(uint8_t *sm, uint32_t n, const uint8_t *pk);

#endif /* DROPBEAR_ED25519 */

#endif /* DROPBEAR_ED25519_CRYPTO_H_ */
