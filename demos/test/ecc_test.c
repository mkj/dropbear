#include "test.h"

#ifdef MECC

int ecc_tests (void)
{
  unsigned char buf[4][4096];
  unsigned long x, y, z;
  int           stat, stat2;
  ecc_key usera, userb;
	
  DO(ecc_test ());

  /* make up two keys */
  DO(ecc_make_key (&test_yarrow, find_prng ("yarrow"), 65, &usera));
  DO(ecc_make_key (&test_yarrow, find_prng ("yarrow"), 65, &userb));

  /* make the shared secret */
  x = 4096;
  DO(ecc_shared_secret (&usera, &userb, buf[0], &x));

  y = 4096;
  DO(ecc_shared_secret (&userb, &usera, buf[1], &y));

  if (y != x) {
    printf ("ecc Shared keys are not same size.");
    return 1;
  }

  if (memcmp (buf[0], buf[1], x)) {
    printf ("ecc Shared keys not same contents.");
    return 1;
  }

  /* now export userb */
  y = 4096;
  DO(ecc_export (buf[1], &y, PK_PUBLIC, &userb));
  ecc_free (&userb);

  /* import and make the shared secret again */
  DO(ecc_import (buf[1], y, &userb));

  z = 4096;
  DO(ecc_shared_secret (&usera, &userb, buf[2], &z));

  if (z != x) {
    printf ("failed.  Size don't match?");
    return 1;
  }
  if (memcmp (buf[0], buf[2], x)) {
    printf ("Failed.  Content didn't match.");
    return 1;
  }
  ecc_free (&usera);
  ecc_free (&userb);

/* test encrypt_key */
  ecc_make_key (&test_yarrow, find_prng ("yarrow"), 65, &usera);
  for (x = 0; x < 32; x++) {
    buf[0][x] = x;
  }
  y = sizeof (buf[1]);
  DO(ecc_encrypt_key (buf[0], 32, buf[1], &y, &test_yarrow, find_prng ("yarrow"), find_hash ("sha256"), &usera));
  zeromem (buf[0], sizeof (buf[0]));
  x = sizeof (buf[0]);
  DO(ecc_decrypt_key (buf[1], y, buf[0], &x, &usera));
  if (x != 32) {
    printf ("Failed (length)");
    return 1;
  }
  for (x = 0; x < 32; x++)
    if (buf[0][x] != x) {
      printf ("Failed (contents)");
      return 1;
    }
/* test sign_hash */
  for (x = 0; x < 16; x++) {
    buf[0][x] = x;
  }
  x = sizeof (buf[1]);
  DO(ecc_sign_hash (buf[0], 16, buf[1], &x, &test_yarrow, find_prng ("yarrow"), &usera));
  DO(ecc_verify_hash (buf[1], x, buf[0], 16, &stat, &usera));
  buf[0][0] ^= 1;
  DO(ecc_verify_hash (buf[1], x, buf[0], 16, &stat2, &usera));
  if (!(stat == 1 && stat2 == 0)) { 
    printf("ecc_verify_hash failed");
    return 1;
  }
  ecc_free (&usera);
  return 0;
}

#else

int ecc_tests(void)
{
   printf("NOP");
   return 0;
}

#endif
