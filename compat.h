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

#ifndef HAVE_BASENAME
char *basename(const char* path);
#endif

#ifndef HAVE_GETUSERSHELL
char *getusershell();
void setusershell();
void endusershell();
#endif

#endif /* _COMPAT_H_ */
