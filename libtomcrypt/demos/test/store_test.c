#include "test.h"

int store_test(void)
{
  unsigned char buf[8];
  unsigned long L;
  ulong64 LL;

  L = 0x12345678UL;
  STORE32L (L, &buf[0]);
  L = 0;
  LOAD32L (L, &buf[0]);
  if (L != 0x12345678UL) {
    printf ("LOAD/STORE32 Little don't work");
    return 1;
  }
  LL = CONST64 (0x01020304050607);
  STORE64L (LL, &buf[0]);
  LL = 0;
  LOAD64L (LL, &buf[0])
    if (LL != CONST64 (0x01020304050607)) {
    printf ("LOAD/STORE64 Little don't work");
    return 1;
  }

  L = 0x12345678UL;
  STORE32H (L, &buf[0]);
  L = 0;
  LOAD32H (L, &buf[0]);
  if (L != 0x12345678UL) {
    printf ("LOAD/STORE32 High don't work, %08lx", L);
    return 1;
  }
  LL = CONST64 (0x01020304050607);
  STORE64H (LL, &buf[0]);
  LL = 0;
  LOAD64H (LL, &buf[0])
    if (LL != CONST64 (0x01020304050607)) {
    printf ("LOAD/STORE64 High don't work");
    return 1;
  }
  return 0;
}
