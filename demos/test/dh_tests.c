#include "test.h"

int dh_tests (void)
{
  unsigned char buf[3][4096];
  unsigned long x, y, z;
  int           stat, stat2;
  dh_key        usera, userb;

  DO(dh_test());

  /* make up two keys */
  DO(dh_make_key (&test_yarrow, find_prng ("yarrow"), 96, &usera));
  DO(dh_make_key (&test_yarrow, find_prng ("yarrow"), 96, &userb));

  /* make the shared secret */
  x = 4096;
  DO(dh_shared_secret (&usera, &userb, buf[0], &x));

  y = 4096;
  DO(dh_shared_secret (&userb, &usera, buf[1], &y));
  if (y != x) {
    printf ("DH Shared keys are not same size.\n");
    return 1;
  }
  if (memcmp (buf[0], buf[1], x)) {
    printf ("DH Shared keys not same contents.\n");
    return 1;
  }

  /* now export userb */
  y = 4096;
  DO(dh_export (buf[1], &y, PK_PUBLIC, &userb));
	  dh_free (&userb);

  /* import and make the shared secret again */
  DO(dh_import (buf[1], y, &userb));
  z = 4096;
  DO(dh_shared_secret (&usera, &userb, buf[2], &z));

  if (z != x) {
    printf ("failed.  Size don't match?\n");
    return 1;
  }
  if (memcmp (buf[0], buf[2], x)) {
    printf ("Failed.  Content didn't match.\n");
    return 1;
  }
  dh_free (&usera);
  dh_free (&userb);

/* test encrypt_key */
  dh_make_key (&test_yarrow, find_prng ("yarrow"), 128, &usera);
  for (x = 0; x < 16; x++) {
    buf[0][x] = x;
  }
  y = sizeof (buf[1]);
  DO(dh_encrypt_key (buf[0], 16, buf[1], &y, &test_yarrow, find_prng ("yarrow"), find_hash ("md5"), &usera));
  zeromem (buf[0], sizeof (buf[0]));
  x = sizeof (buf[0]);
  DO(dh_decrypt_key (buf[1], y, buf[0], &x, &usera));
  if (x != 16) {
    printf ("Failed (length)\n");
    return 1;
  }
  for (x = 0; x < 16; x++)
    if (buf[0][x] != x) {
      printf ("Failed (contents)\n");
      return 1;
    }

/* test sign_hash */
  for (x = 0; x < 16; x++) {
     buf[0][x] = x;
  }
  x = sizeof (buf[1]);
  DO(dh_sign_hash (buf[0], 16, buf[1], &x, &test_yarrow		, find_prng ("yarrow"), &usera));
  DO(dh_verify_hash (buf[1], x, buf[0], 16, &stat, &usera));
  buf[0][0] ^= 1;
  DO(dh_verify_hash (buf[1], x, buf[0], 16, &stat2, &usera));
  if (!(stat == 1 && stat2 == 0)) { 
     printf("dh_sign/verify_hash %d %d", stat, stat2);
     return 1;
  }
  dh_free (&usera);
  return 0;
}
