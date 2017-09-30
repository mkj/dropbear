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
#include "dbutil.h"
#include "ed25519.h"
#include "buffer.h"
#include "ssh.h"

/* Handle ed25519 (Edwards 25519 elliptic curve)
 * operations, such as key reading, signing, verification. Key generation
 * will be in gened25519.c, since it isn't required in the server itself.
 */

#ifdef DROPBEAR_ED25519 

/* Load a ed25519 key from a buffer, initialising the values.
 * The key will have the same format as buf_put_ed25519_key.
 * These should be freed with ed25519_key_free.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_get_ed25519_pub_key(buffer* buf, dropbear_ed25519_key *key) {
	/* Format (same as the base64-encoded 2nd word in each line of
	 * ~/.ssh/authorized_keys used by dropbear and OpenSSH):
	 *
	 * "'\0\0\0\x0bssh-ed25519\0\0\0 " + pk,
	 * where pk is 32 bytes of public key.
	 * It's 51 bytes in total.
	 */
	dropbear_log(LOG_ERR, "!! buf_get_ed25519_pub_key");
	if (buf->pos + 51 > buf->len ||
	    0 != memcmp(buf->data + buf->pos, "\0\0\0\x0bssh-ed25519\0\0\0 ", 19)
	   ) return DROPBEAR_FAILURE;
	dropbear_log(LOG_ERR, "!! buf_get_ed25519_pub_key SUCCESS");
	memset(key->spk, '\0', 32);  /* Secret key not known. */
	memcpy(key->spk + 32, buf->data + buf->pos + 19, 32);
	buf->pos += 51;
	return DROPBEAR_SUCCESS;
}

/* Loads a private ed25519 key from a buffer
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_get_ed25519_priv_key(buffer* buf, dropbear_ed25519_key *key) {
	/* Format (not shared with OpenSSH):
	 *
	 * "'\0\0\0\x0bssh-ed25519\0\0\0@" + sk + pk,
	 * where sk is 32 bytes of secret key (private key).
	 * where pk is 32 bytes of public key.
	 * It's 83 bytes in total.
	 */
	dropbear_log(LOG_ERR, "!! buf_get_ed25519_priv_key");
	if (buf->pos + 83 > buf->len ||
	    0 != memcmp(buf->data + buf->pos, "\0\0\0\x0bssh-ed25519\0\0\0@", 19)
	   ) return DROPBEAR_FAILURE;
	dropbear_log(LOG_ERR, "!! buf_get_ed25519_priv_key SUCCESS");
	memcpy(key->spk, buf->data + buf->pos + 19, 64);
	buf->pos += 83;
	return DROPBEAR_SUCCESS;
}
	

/* Clear and free the memory used by a public or private key */
void ed25519_key_free(dropbear_ed25519_key *key) {
	dropbear_log(LOG_ERR, "!! ed25519_key_free");
	(void)key;
}

/* put the ed25519 public key into the buffer in the required format. */
void buf_put_ed25519_pub_key(buffer* buf, dropbear_ed25519_key *key) {
	dropbear_log(LOG_ERR, "!! buf_put_ed25519_pub_key");
	dropbear_assert(key != NULL);
	buf_putstring(buf, SSH_SIGNKEY_ED25519, SSH_SIGNKEY_ED25519_LEN);
	buf_putstring(buf, key->spk + 32, 32);
}

/* put the ed25519 private key into the buffer in the required format. */
void buf_put_ed25519_priv_key(buffer* buf, dropbear_ed25519_key *key) {
	dropbear_log(LOG_ERR, "!! buf_put_ed25519_priv_key");
	dropbear_assert(key != NULL);
	buf_putstring(buf, SSH_SIGNKEY_ED25519, SSH_SIGNKEY_ED25519_LEN);
	buf_putstring(buf, key->spk, 64);
}

#ifdef DROPBEAR_SIGNKEY_VERIFY
/* Verify a ed25519 signature (in buf) made on data by the key given. 
 * returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_ed25519_verify(buffer* buf, dropbear_ed25519_key *key, buffer *data_buf) {
	(void)buf; (void)key; (void)data_buf;
	dropbear_log(LOG_ERR, "!! buf_ed25519_verify");
	return DROPBEAR_FAILURE;
	dropbear_log(LOG_ERR, "!! buf_ed25519_verify SUCCESS");
	return DROPBEAR_SUCCESS;  /* !! TODO(pts): Implement this. */
}
#endif /* DROPBEAR_SIGNKEY_VERIFY */

/* Sign the data presented with key, writing the signature contents
 * to buf */
void buf_put_ed25519_sign(buffer* buf, dropbear_ed25519_key *key, buffer *data_buf) {
	(void)buf; (void)key; (void)data_buf;
	dropbear_log(LOG_ERR, "!! buf_put_ed25519_sign");
	dropbear_exit("!! buf_put_ed25519_sign not implemented.");
}

#endif /* DROPBEAR_ED25519 */
