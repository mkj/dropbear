#include <tomcrypt_test.h>

#ifdef MECC

static int sizes[] = {
#ifdef ECC192
24,
#endif
#ifdef ECC224
28,
#endif
#ifdef ECC256
32,
#endif
#ifdef ECC384
48,
#endif
#ifdef ECC512
65
#endif
};

int ecc_tests (void)
{
  unsigned char buf[4][4096];
  unsigned long x, y, z, s;
  int           stat, stat2;
  ecc_key usera, userb, pubKey, privKey;
	
  DO(ecc_test ());

  for (s = 0; s < (int)(sizeof(sizes)/sizeof(sizes[0])); s++) {
     /* make up two keys */
     DO(ecc_make_key (&yarrow_prng, find_prng ("yarrow"), sizes[s], &usera));
     DO(ecc_make_key (&yarrow_prng, find_prng ("yarrow"), sizes[s], &userb));

     /* make the shared secret */
     x = 4096;
     DO(ecc_shared_secret (&usera, &userb, buf[0], &x));

     y = 4096;
     DO(ecc_shared_secret (&userb, &usera, buf[1], &y));

     if (y != x) {
       fprintf(stderr, "ecc Shared keys are not same size.");
       return 1;
     }

     if (memcmp (buf[0], buf[1], x)) {
       fprintf(stderr, "ecc Shared keys not same contents.");
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
       fprintf(stderr, "failed.  Size don't match?");
       return 1;
     }
     if (memcmp (buf[0], buf[2], x)) {
       fprintf(stderr, "Failed.  Contents didn't match.");
       return 1;
     }
     ecc_free (&usera);
     ecc_free (&userb);

     /* test encrypt_key */
     DO(ecc_make_key (&yarrow_prng, find_prng ("yarrow"), sizes[s], &usera));

     /* export key */
     x = sizeof(buf[0]);
     DO(ecc_export(buf[0], &x, PK_PUBLIC, &usera));
     DO(ecc_import(buf[0], x, &pubKey));
     x = sizeof(buf[0]);
     DO(ecc_export(buf[0], &x, PK_PRIVATE, &usera));
     DO(ecc_import(buf[0], x, &privKey));

     for (x = 0; x < 32; x++) {
        buf[0][x] = x;
     }
     y = sizeof (buf[1]);
     DO(ecc_encrypt_key (buf[0], 32, buf[1], &y, &yarrow_prng, find_prng ("yarrow"), find_hash ("sha256"), &pubKey));
     zeromem (buf[0], sizeof (buf[0]));
     x = sizeof (buf[0]);
     DO(ecc_decrypt_key (buf[1], y, buf[0], &x, &privKey));
     if (x != 32) {
       fprintf(stderr, "Failed (length)");
       return 1;
     }
     for (x = 0; x < 32; x++) {
        if (buf[0][x] != x) {
           fprintf(stderr, "Failed (contents)");
           return 1;
        }
     }
     /* test sign_hash */
     for (x = 0; x < 16; x++) {
        buf[0][x] = x;
     }
     x = sizeof (buf[1]);
     DO(ecc_sign_hash (buf[0], 16, buf[1], &x, &yarrow_prng, find_prng ("yarrow"), &privKey));
     DO(ecc_verify_hash (buf[1], x, buf[0], 16, &stat, &pubKey));
     buf[0][0] ^= 1;
     DO(ecc_verify_hash (buf[1], x, buf[0], 16, &stat2, &privKey));
     if (!(stat == 1 && stat2 == 0)) { 
        fprintf(stderr, "ecc_verify_hash failed %d, %d, ", stat, stat2);
        return 1;
     }
     ecc_free (&usera); 
     ecc_free (&pubKey);
     ecc_free (&privKey);
  }
  return 0;
}

#else

int ecc_tests(void)
{
   fprintf(stderr, "NOP");
   return 0;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/testprof/ecc_test.c,v $ */
/* $Revision: 1.9 $ */
/* $Date: 2005/06/14 19:43:29 $ */
