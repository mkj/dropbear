#include "test.h"

/* Test store/load macros with offsets */
int store_test(void)
{
  unsigned char buf[24];
  unsigned long L, L1;
  int y;
  ulong64 LL, LL1;

  L = 0x12345678UL;
  for (y = 0; y < 4; y++) {
      STORE32L(L, buf + y);
      LOAD32L(L1, buf + y);
      if (L1 != L) {
         fprintf(stderr, "\n32L failed at offset %d\n", y);
         return 1;
      }
      STORE32H(L, buf + y);
      LOAD32H(L1, buf + y);
      if (L1 != L) {
         fprintf(stderr, "\n32H failed at offset %d\n", y);
         return 1;
      }
  }

  LL = CONST64 (0x01020304050607);
  for (y = 0; y < 8; y++) {
      STORE64L(LL, buf + y);
      LOAD64L(LL1, buf + y);
      if (LL1 != LL) {
         fprintf(stderr, "\n64L failed at offset %d\n", y);
         return 1;
      }
      STORE64H(LL, buf + y);
      LOAD64H(LL1, buf + y);
      if (LL1 != LL) {
         fprintf(stderr, "\n64H failed at offset %d\n", y);
         return 1;
      }
  }

  return 0;
}
