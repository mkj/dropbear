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

/* The "NULL" encryption cipher, as defined in rfc 2410 */

#include "includes.h"

static int
null_setup (const unsigned char *key, int keylen, int num_rounds,
        symmetric_key * skey)
{
  return CRYPT_OK;
}

static void
null_ecb_encrypt (const unsigned char *pt, unsigned char *ct,
          symmetric_key * key)
{
  memcpy (ct, pt, 8);
}

static void
null_ecb_decrypt (const unsigned char *ct, unsigned char *pt,
          symmetric_key * key)
{
  memcpy (pt, ct, 8);
}

static int
null_keysize (int *desired_keysize)
{
  return CRYPT_OK;
}

const struct _cipher_descriptor null_desc = {
  "nullcrypt",
  255,
  8, 8, 8, 1,
  &null_setup,
  &null_ecb_encrypt,
  &null_ecb_decrypt,
  NULL, /* test */
  &null_keysize
};
