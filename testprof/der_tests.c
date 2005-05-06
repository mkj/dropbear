#include <tomcrypt_test.h>

#ifndef LTC_DER

int der_tests(void)
{
   printf("NOP");
   return 0;
}

#else

int der_tests(void)
{
   unsigned long x, y, z, zz;
   unsigned char buf[2][4096];
   mp_int a, b, c, d, e, f, g;

   DO(mpi_to_ltc_error(mp_init_multi(&a, &b, &c, &d, &e, &f, &g, NULL)));
   for (zz = 0; zz < 16; zz++) {
      for (z = 0; z < 1024; z++) {
         if (yarrow_read(buf[0], z, &yarrow_prng) != z) {
            printf("Failed to read %lu bytes from yarrow\n", z);
            return 1;
         }
         DO(mpi_to_ltc_error(mp_read_unsigned_bin(&a, buf[0], z)));
         x = sizeof(buf[0]);
         DO(der_encode_integer(&a, buf[0], &x));
         y = x;
         mp_zero(&b);
         DO(der_decode_integer(buf[0], &y, &b));
         if (y != x || mp_cmp(&a, &b) != MP_EQ) {
            printf("%lu: %lu vs %lu\n", z, x, y);
#ifdef BN_MP_TORADIX_C
            mp_todecimal(&a, buf[0]);
            mp_todecimal(&b, buf[1]);
            printf("a == %s\nb == %s\n", buf[0], buf[1]);
#endif
            mp_clear_multi(&a, &b, &c, &d, &e, &f, &g, NULL);
            return 1;
         }
      }
   }
   

/* test the multi */
   mp_set(&a, 1);
   x = sizeof(buf[0]);
   DO(der_put_multi_integer(buf[0], &x, &a, NULL));
   y = x;
   mp_zero(&a);
   DO(der_get_multi_integer(buf[0], &y, &a, NULL));   
   if (x != y || mp_cmp_d(&a, 1)) {
      printf("%lu, %lu, %d\n", x, y, mp_cmp_d(&a, 1));
      mp_clear_multi(&a, &b, &c, &d, &e, &f, &g, NULL);
      return 1;
   }   

   mp_set(&a, 1);
   mp_set(&b, 2);
   x = sizeof(buf[0]);
   DO(der_put_multi_integer(buf[0], &x, &a, &b, NULL));
   y = x;
   mp_zero(&a);
   mp_zero(&b);
   DO(der_get_multi_integer(buf[0], &y, &a, &b, NULL));   
   if (x != y || mp_cmp_d(&a, 1) || mp_cmp_d(&b, 2)) {
      printf("%lu, %lu, %d, %d\n", x, y, mp_cmp_d(&a, 1), mp_cmp_d(&b, 2));
      mp_clear_multi(&a, &b, &c, &d, &e, &f, &g, NULL);
      return 1;
   }   

   mp_set(&a, 1);
   mp_set(&b, 2);
   mp_set(&c, 3);
   x = sizeof(buf[0]);
   DO(der_put_multi_integer(buf[0], &x, &a, &b, &c, NULL));
   y = x;
   mp_zero(&a);
   mp_zero(&b);
   mp_zero(&c);
   DO(der_get_multi_integer(buf[0], &y, &a, &b, &c, NULL));   
   if (x != y || mp_cmp_d(&a, 1) || mp_cmp_d(&b, 2) || mp_cmp_d(&c, 3)) {
      printf("%lu, %lu, %d, %d, %d\n", x, y, mp_cmp_d(&a, 1), mp_cmp_d(&b, 2), mp_cmp_d(&c, 3));
      mp_clear_multi(&a, &b, &c, &d, &e, &f, &g, NULL);
      return 1;
   }   


   mp_clear_multi(&a, &b, &c, &d, &e, &f, &g, NULL);
   return 0;
}

#endif
