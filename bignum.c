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
 * furnished to do so, subject to the following condition:
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

#include "options.h"
#include "util.h"
#include "stdlib.h"
#include "libtomcrypt/mycrypt.h"

/* wrapper for mp_init to handle errors */
void m_mp_init(mp_int *mp) {

	if (mp_init(mp) != MP_OKAY) {
		dropbear_exit("error initialising mpint");
	}
}

/* convert an unsigned mp into an array of bytes, malloced.
 * This array must be freed after use, len contains the length of the array,
 * if len != NULL */
unsigned char* mptobytes(mp_int *mp, int *len) {
	
	unsigned char* ret;
	int size;

	size = mp_unsigned_bin_size(mp);
	ret = m_malloc(size);
	if (mp_to_unsigned_bin(mp, ret) != MP_OKAY) {
		dropbear_exit("error converting mp_int to bytes");
	}
	if (len != NULL) {
		*len = size;
	}
	return ret;
}

void bytestomp(mp_int *mp, unsigned char* bytes, unsigned int len) {

	if (mp_read_unsigned_bin(mp, bytes, len) != MP_OKAY) {
		dropbear_exit("error converting bytes to mp_int");
	}
}

/* hash the ssh representation of the mp_int mp */
void sha1_process_mp(hash_state *hs, mp_int *mp) {

	int i;
	buffer * buf;

	buf = buf_new(1000);
	buf_putmpint(buf, mp);
	i = buf->pos;
	buf_setpos(buf, 0);
	sha1_process(hs, buf_getptr(buf, i), i);
	buf_free(buf);
}
