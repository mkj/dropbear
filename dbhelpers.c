#include "dbhelpers.h"
#include "includes.h"

/* Erase data */
void m_burn(void *data, unsigned int len) {

#if defined(HAVE_MEMSET_S)
	memset_s(data, len, 0x0, len);
#elif defined(HAVE_EXPLICIT_BZERO)
	explicit_bzero(data, len);
#else
	void *p = data;
	memset(p, 0x0, len);
#endif
}


