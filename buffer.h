#ifndef _BUFFER_H_

#define _BUFFER_H_

#include "options.h"

#define MAX_STRING_LEN MAX_PACKET_LEN
struct buf {

	unsigned char * data;
	unsigned int len; /* the used size */
	unsigned int pos;
	unsigned int size; /* the memory size */

};

typedef struct buf buffer;

buffer * buf_new(unsigned int size);
void buf_init(buffer* buf, unsigned int size);
void buf_resize(buffer *buf, unsigned int newsize);
void buf_free(buffer* buf);
void buf_clear(buffer* buf);
void buf_burn(buffer* buf);
buffer* buf_newcopy(buffer* buf, int lenonly);
void buf_setlen(buffer* buf, unsigned int len);
void buf_incrlen(buffer* buf, unsigned int incr);
void buf_setpos(buffer* buf, unsigned int pos);
void buf_incrpos(buffer* buf, int incr); /* -ve is ok, to go backwards */
void buf_incrwritepos(buffer* buf, unsigned int incr);
unsigned char buf_getbyte(buffer* buf);
void buf_putbyte(buffer* buf, unsigned char val);
unsigned char* buf_getptr(buffer* buf, unsigned int len);
unsigned char* buf_getwriteptr(buffer* buf, unsigned int len);
unsigned char* buf_getstring(buffer* buf, unsigned int *retlen);
void buf_putint(buffer* buf, unsigned int val);
void buf_putstring(buffer* buf, const unsigned char* str, unsigned int len);
void buf_putbytes(buffer *buf, const unsigned char *bytes, unsigned int len);
void buf_putmpint(buffer* buf, mp_int * mp);
int buf_getmpint(buffer* buf, mp_int* mp);
unsigned int buf_getint(buffer* buf);

#endif /* _BUFFER_H_ */
