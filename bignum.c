#include "options.h"
#include "util.h"
#include "stdlib.h"
#include "libtomcrypt/mpi.h"
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
