#ifndef _UTIL_H_

#define _UTIL_H_

#include <sys/types.h>

#include "options.h"
#include "buffer.h"

void dropbear_msg(const char* format, ...);
void dropbear_exit(const char* format, ...);
void dropbear_close(const char* format, ...);
#ifdef DEBUG_TRACE
void dropbear_trace(const char* format, ...);
#endif
void printhex(unsigned char* buf, int len);
int readln(int fd, char* buf, int count);
int writeln(int fd, char* str);
int buf_readfile(buffer* buf, char* filename);

void * m_malloc(size_t size);
void * m_realloc(void* ptr, size_t size);
#define m_free(X) __m_free(X); (X) = NULL;
void __m_free(void* ptr);
void m_burn(void* data, unsigned int len);

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#endif /* _UTIL_H_ */
