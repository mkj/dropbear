#ifndef _BIGNUM_H_
#define _BIGNUM_H_

#include "libtomcrypt/mycrypt.h"

void m_mp_init(mp_int *mp);
unsigned char* mptobytes(mp_int *mp, int *len);
void bytestomp(mp_int *mp, unsigned char* bytes, unsigned int len);
void sha1_process_mp(hash_state *hs, mp_int *mp);

#endif /* _BIGNUM_H_ */
