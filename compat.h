#ifndef _COMPAT_H_
#define _COMPAT_H_

#include "includes.h"

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif

#endif /* _COMPAT_H_ */
