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

#ifndef _DBUTIL_H_

#define _DBUTIL_H_

#include "includes.h"
#include "buffer.h"

#ifndef DISABLE_SYSLOG
void startsyslog();
#endif
extern int usingsyslog;
void dropbear_exit(const char* format, ...);
void dropbear_close(const char* format, ...);
void dropbear_log(int priority, const char* format, ...);
#ifdef DEBUG_TRACE
void dropbear_trace(const char* format, ...);
void printhex(unsigned char* buf, int len);
#endif
char * stripcontrol(const char * text);
unsigned char * getaddrstring(struct sockaddr * addr);
char* getaddrhostname(struct sockaddr * addr);
int buf_readfile(buffer* buf, const char* filename);

int m_close(int fd);
void * m_malloc(size_t size);
void * m_realloc(void* ptr, size_t size);
#define m_free(X) __m_free(X); (X) = NULL;
void __m_free(void* ptr);
void m_burn(void* data, unsigned int len);

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#endif /* _DBUTIL_H_ */
