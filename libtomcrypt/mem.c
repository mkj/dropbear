#include "mycrypt.h"

void zeromem(void *dst, size_t len)
{
 unsigned char *mem = (unsigned char *)dst;
 _ARGCHK(dst != NULL);
 while (len-- > 0)
    *mem++ = 0;
}

void burn_stack(unsigned long len)
{
   unsigned char buf[32];
   zeromem(buf, sizeof(buf));
   if (len > (unsigned long)sizeof(buf))
      burn_stack(len - sizeof(buf));
}


