#include <tomcrypt_test.h>

#ifndef LTC_DER

int der_tests(void)
{
   fprintf(stderr, "NOP");
   return 0;
}

#else

static int der_choice_test(void)
{
   ltc_asn1_list types[7], host[1];
   unsigned char bitbuf[10], octetbuf[10], ia5buf[10], printbuf[10], outbuf[256];
   unsigned long integer, oidbuf[10], outlen, inlen, x, y;
   mp_int        mpinteger;
   ltc_utctime   utctime = { 91, 5, 6, 16, 45, 40, 1, 7, 0 };

   /* setup variables */
   for (x = 0; x < sizeof(bitbuf); x++)   { bitbuf[x]   = x & 1; }
   for (x = 0; x < sizeof(octetbuf); x++) { octetbuf[x] = x;     }
   for (x = 0; x < sizeof(ia5buf); x++)   { ia5buf[x]   = 'a';   }
   for (x = 0; x < sizeof(printbuf); x++) { printbuf[x] = 'a';   }
   integer = 1;
   for (x = 0; x < sizeof(oidbuf)/sizeof(oidbuf[0]); x++)   { oidbuf[x] = x + 1;   }
   DO(mpi_to_ltc_error(mp_init(&mpinteger)));

   for (x = 0; x < 14; x++) {
       /* setup list */
       LTC_SET_ASN1(types, 0, LTC_ASN1_PRINTABLE_STRING, printbuf, sizeof(printbuf));
       LTC_SET_ASN1(types, 1, LTC_ASN1_BIT_STRING, bitbuf, sizeof(bitbuf));
       LTC_SET_ASN1(types, 2, LTC_ASN1_OCTET_STRING, octetbuf, sizeof(octetbuf));
       LTC_SET_ASN1(types, 3, LTC_ASN1_IA5_STRING, ia5buf, sizeof(ia5buf));
       if (x > 7) {
          LTC_SET_ASN1(types, 4, LTC_ASN1_SHORT_INTEGER, &integer, 1);
       } else {
          LTC_SET_ASN1(types, 4, LTC_ASN1_INTEGER, &mpinteger, 1);
       }
       LTC_SET_ASN1(types, 5, LTC_ASN1_OBJECT_IDENTIFIER, oidbuf, sizeof(oidbuf)/sizeof(oidbuf[0]));
       LTC_SET_ASN1(types, 6, LTC_ASN1_UTCTIME, &utctime, 1);

       LTC_SET_ASN1(host, 0, LTC_ASN1_CHOICE, types, 7);

       
       /* encode */
       outlen = sizeof(outbuf);
       DO(der_encode_sequence(&types[x>6?x-7:x], 1, outbuf, &outlen));

       /* decode it */
       inlen = outlen;
       DO(der_decode_sequence(outbuf, inlen, &host, 1));

       for (y = 0; y < 7; y++) {
           if (types[y].used && y != (x>6?x-7:x)) {
               fprintf(stderr, "CHOICE, flag %lu in trial %lu was incorrectly set to one\n", y, x);
               return 1;
           }
           if (!types[y].used && y == (x>6?x-7:x)) {
               fprintf(stderr, "CHOICE, flag %lu in trial %lu was incorrectly set to zero\n", y, x);
               return 1;
           }
      }
  }
  mp_clear(&mpinteger);
  return 0;
}
   

int der_tests(void)
{
   unsigned long x, y, z, zz, oid[2][32];
   unsigned char buf[3][2048];
   mp_int a, b, c, d, e, f, g;

   static const unsigned char rsa_oid_der[] = { 0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d };
   static const unsigned long rsa_oid[]     = { 1, 2, 840, 113549 };

   static const unsigned char rsa_ia5[]     = "test1@rsa.com";
   static const unsigned char rsa_ia5_der[] = { 0x16, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31,
                                                0x40, 0x72, 0x73, 0x61, 0x2e, 0x63, 0x6f, 0x6d };

   static const unsigned char rsa_printable[] = "Test User 1";
   static const unsigned char rsa_printable_der[] = { 0x13, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 
                                                      0x73, 0x65, 0x72, 0x20, 0x31 };

   static const ltc_utctime   rsa_time1 = { 91, 5, 6, 16, 45, 40, 1, 7, 0 };
   static const ltc_utctime   rsa_time2 = { 91, 5, 6, 23, 45, 40, 0, 0, 0 };
   ltc_utctime                tmp_time;

   static const unsigned char rsa_time1_der[] = { 0x17, 0x11, 0x39, 0x31, 0x30, 0x35, 0x30, 0x36, 0x31, 0x36, 0x34, 0x35, 0x34, 0x30, 0x2D, 0x30, 0x37, 0x30, 0x30 };
   static const unsigned char rsa_time2_der[] = { 0x17, 0x0d, 0x39, 0x31, 0x30, 0x35, 0x30, 0x36, 0x32, 0x33, 0x34, 0x35, 0x34, 0x30, 0x5a };

   DO(mpi_to_ltc_error(mp_init_multi(&a, &b, &c, &d, &e, &f, &g, NULL)));
   for (zz = 0; zz < 16; zz++) {
      for (z = 0; z < 1024; z++) {
         if (yarrow_read(buf[0], z, &yarrow_prng) != z) {
            fprintf(stderr, "Failed to read %lu bytes from yarrow\n", z);
            return 1;
         }
         DO(mpi_to_ltc_error(mp_read_unsigned_bin(&a, buf[0], z)));
         if (mp_iszero(&a) == MP_NO) { a.sign = buf[0][0] & 1 ? MP_ZPOS : MP_NEG; }
         x = sizeof(buf[0]);
         DO(der_encode_integer(&a, buf[0], &x));
         DO(der_length_integer(&a, &y));
         if (y != x) { fprintf(stderr, "DER INTEGER size mismatch\n"); return 1; }
         mp_zero(&b);
         DO(der_decode_integer(buf[0], y, &b));
         if (y != x || mp_cmp(&a, &b) != MP_EQ) {
            fprintf(stderr, "%lu: %lu vs %lu\n", z, x, y);
#ifdef BN_MP_TORADIX_C
            mp_todecimal(&a, buf[0]);
            mp_todecimal(&b, buf[1]);
            fprintf(stderr, "a == %s\nb == %s\n", buf[0], buf[1]);
#endif
            mp_clear_multi(&a, &b, &c, &d, &e, &f, &g, NULL);
            return 1;
         }
      }
   }

/* test short integer */
   for (zz = 0; zz < 256; zz++) {
      for (z = 1; z < 4; z++) {
         if (yarrow_read(buf[0], z, &yarrow_prng) != z) {
            fprintf(stderr, "Failed to read %lu bytes from yarrow\n", z);
            return 1;
         }
         /* encode with normal */
         DO(mpi_to_ltc_error(mp_read_unsigned_bin(&a, buf[0], z)));

         x = sizeof(buf[0]);
         DO(der_encode_integer(&a, buf[0], &x));

         /* encode with short */
         y = sizeof(buf[1]);
         DO(der_encode_short_integer(mp_get_int(&a), buf[1], &y));
         if (x != y || memcmp(buf[0], buf[1], x)) {
            fprintf(stderr, "DER INTEGER short encoding failed, %lu, %lu\n", x, y);
            for (z = 0; z < x; z++) fprintf(stderr, "%02x ", buf[0][z]); fprintf(stderr, "\n");
            for (z = 0; z < y; z++) fprintf(stderr, "%02x ", buf[1][z]); fprintf(stderr, "\n");
            mp_clear_multi(&a, &b, &c, &d, &e, &f, &g, NULL);
            return 1;
         }

         /* decode it */
         x = 0;
         DO(der_decode_short_integer(buf[1], y, &x));
         if (x != mp_get_int(&a)) {
            fprintf(stderr, "DER INTEGER short decoding failed, %lu, %lu\n", x, mp_get_int(&a));
            mp_clear_multi(&a, &b, &c, &d, &e, &f, &g, NULL);
            return 1;
         }
      }
   } 
   mp_clear_multi(&a, &b, &c, &d, &e, &f, &g, NULL);

   
/* Test bit string */
   for (zz = 1; zz < 1536; zz++) {
       yarrow_read(buf[0], zz, &yarrow_prng);
       for (z = 0; z < zz; z++) {
           buf[0][z] &= 0x01;
       }
       x = sizeof(buf[1]);
       DO(der_encode_bit_string(buf[0], zz, buf[1], &x));
       DO(der_length_bit_string(zz, &y));
       if (y != x) { 
          fprintf(stderr, "\nDER BIT STRING length of encoded not match expected : %lu, %lu, %lu\n", z, x, y);
          return 1;
       }

       y = sizeof(buf[2]);
       DO(der_decode_bit_string(buf[1], x, buf[2], &y));
       if (y != zz || memcmp(buf[0], buf[2], zz)) {
          fprintf(stderr, "%lu, %lu, %d\n", y, zz, memcmp(buf[0], buf[2], zz));
          return 1;
       }
   }

/* Test octet string */
   for (zz = 1; zz < 1536; zz++) {
       yarrow_read(buf[0], zz, &yarrow_prng);
       x = sizeof(buf[1]);
       DO(der_encode_octet_string(buf[0], zz, buf[1], &x));
       DO(der_length_octet_string(zz, &y));
       if (y != x) { 
          fprintf(stderr, "\nDER OCTET STRING length of encoded not match expected : %lu, %lu, %lu\n", z, x, y);
          return 1;
       }
       y = sizeof(buf[2]);
       DO(der_decode_octet_string(buf[1], x, buf[2], &y));
       if (y != zz || memcmp(buf[0], buf[2], zz)) {
          fprintf(stderr, "%lu, %lu, %d\n", y, zz, memcmp(buf[0], buf[2], zz));
          return 1;
       }
   }

/* test OID */
   x = sizeof(buf[0]);
   DO(der_encode_object_identifier(rsa_oid, sizeof(rsa_oid)/sizeof(rsa_oid[0]), buf[0], &x));
   if (x != sizeof(rsa_oid_der) || memcmp(rsa_oid_der, buf[0], x)) {
      fprintf(stderr, "rsa_oid_der encode failed to match, %lu, ", x);
      for (y = 0; y < x; y++) fprintf(stderr, "%02x ", buf[0][y]);
      fprintf(stderr, "\n");
      return 1;
   }

   y = sizeof(oid[0])/sizeof(oid[0][0]);
   DO(der_decode_object_identifier(buf[0], x, oid[0], &y));
   if (y != sizeof(rsa_oid)/sizeof(rsa_oid[0]) || memcmp(rsa_oid, oid[0], sizeof(rsa_oid))) {
      fprintf(stderr, "rsa_oid_der decode failed to match, %lu, ", y);
      for (z = 0; z < y; z++) fprintf(stderr, "%lu ", oid[0][z]);
      fprintf(stderr, "\n");
      return 1;
   }

   /* do random strings */
   for (zz = 0; zz < 5000; zz++) {
       /* pick a random number of words */
       yarrow_read(buf[0], 4, &yarrow_prng);
       LOAD32L(z, buf[0]);
       z = 2 + (z % ((sizeof(oid[0])/sizeof(oid[0][0])) - 2));
       
       /* fill them in */
       oid[0][0] = buf[0][0] % 3;
       oid[0][1] = buf[0][1] % 40;

       for (y = 2; y < z; y++) {
          yarrow_read(buf[0], 4, &yarrow_prng);
          LOAD32L(oid[0][y], buf[0]);
       }

       /* encode it */
       x = sizeof(buf[0]);
       DO(der_encode_object_identifier(oid[0], z, buf[0], &x));
       DO(der_length_object_identifier(oid[0], z, &y));
       if (x != y) {
          fprintf(stderr, "Random OID %lu test failed, length mismatch: %lu, %lu\n", z, x, y);
          for (x = 0; x < z; x++) fprintf(stderr, "%lu\n", oid[0][x]);
          return 1;
       }
       
       /* decode it */
       y = sizeof(oid[0])/sizeof(oid[0][0]);
       DO(der_decode_object_identifier(buf[0], x, oid[1], &y));
       if (y != z) {
          fprintf(stderr, "Random OID %lu test failed, decode length mismatch: %lu, %lu\n", z, x, y);
          return 1;
       }
       if (memcmp(oid[0], oid[1], sizeof(oid[0][0]) * z)) {
          fprintf(stderr, "Random OID %lu test failed, decoded values wrong\n", z);
          for (x = 0; x < z; x++) fprintf(stderr, "%lu\n", oid[0][x]); fprintf(stderr, "\n\n Got \n\n");
          for (x = 0; x < z; x++) fprintf(stderr, "%lu\n", oid[1][x]);
          return 1;
       }
   }

/* IA5 string */
   x = sizeof(buf[0]);
   DO(der_encode_ia5_string(rsa_ia5, strlen(rsa_ia5), buf[0], &x));
   if (x != sizeof(rsa_ia5_der) || memcmp(buf[0], rsa_ia5_der, x)) {
      fprintf(stderr, "IA5 encode failed: %lu, %lu\n", x, (unsigned long)sizeof(rsa_ia5_der));
      return 1;
   }
   DO(der_length_ia5_string(rsa_ia5, strlen(rsa_ia5), &y));
   if (y != x) {
      fprintf(stderr, "IA5 length failed to match: %lu, %lu\n", x, y);
      return 1;
   }
   y = sizeof(buf[1]);
   DO(der_decode_ia5_string(buf[0], x, buf[1], &y));
   if (y != strlen(rsa_ia5) || memcmp(buf[1], rsa_ia5, strlen(rsa_ia5))) {
       fprintf(stderr, "DER IA5 failed test vector\n");
       return 1;
   }

/* Printable string */
   x = sizeof(buf[0]);
   DO(der_encode_printable_string(rsa_printable, strlen(rsa_printable), buf[0], &x));
   if (x != sizeof(rsa_printable_der) || memcmp(buf[0], rsa_printable_der, x)) {
      fprintf(stderr, "PRINTABLE encode failed: %lu, %lu\n", x, (unsigned long)sizeof(rsa_printable_der));
      return 1;
   }
   DO(der_length_printable_string(rsa_printable, strlen(rsa_printable), &y));
   if (y != x) {
      fprintf(stderr, "printable length failed to match: %lu, %lu\n", x, y);
      return 1;
   }
   y = sizeof(buf[1]);
   DO(der_decode_printable_string(buf[0], x, buf[1], &y));
   if (y != strlen(rsa_printable) || memcmp(buf[1], rsa_printable, strlen(rsa_printable))) {
       fprintf(stderr, "DER printable failed test vector\n");
       return 1;
   }

/* Test UTC time */
   x = sizeof(buf[0]);
   DO(der_encode_utctime(&rsa_time1, buf[0], &x));
   if (x != sizeof(rsa_time1_der) || memcmp(buf[0], rsa_time1_der, x)) {
      fprintf(stderr, "UTCTIME encode of rsa_time1 failed: %lu, %lu\n", x, (unsigned long)sizeof(rsa_time1_der));
fprintf(stderr, "\n\n");
for (y = 0; y < x; y++) fprintf(stderr, "%02x ", buf[0][y]); printf("\n");

      return 1;
   }
   DO(der_length_utctime(&rsa_time1, &y));
   if (y != x) {
      fprintf(stderr, "UTCTIME length failed to match for rsa_time1: %lu, %lu\n", x, y);
      return 1;
   }
   DO(der_decode_utctime(buf[0], &y, &tmp_time));
   if (y != x || memcmp(&rsa_time1, &tmp_time, sizeof(ltc_utctime))) {
      fprintf(stderr, "UTCTIME decode failed for rsa_time1: %lu %lu\n", x, y);
fprintf(stderr, "\n\n%u %u %u %u %u %u %u %u %u\n\n", 
tmp_time.YY,
tmp_time.MM,
tmp_time.DD,
tmp_time.hh,
tmp_time.mm,
tmp_time.ss,
tmp_time.off_dir,
tmp_time.off_mm,
tmp_time.off_hh);
      return 1;
   }

   x = sizeof(buf[0]);
   DO(der_encode_utctime(&rsa_time2, buf[0], &x));
   if (x != sizeof(rsa_time2_der) || memcmp(buf[0], rsa_time2_der, x)) {
      fprintf(stderr, "UTCTIME encode of rsa_time2 failed: %lu, %lu\n", x, (unsigned long)sizeof(rsa_time1_der));
fprintf(stderr, "\n\n");
for (y = 0; y < x; y++) fprintf(stderr, "%02x ", buf[0][y]); printf("\n");

      return 1;
   }
   DO(der_length_utctime(&rsa_time2, &y));
   if (y != x) {
      fprintf(stderr, "UTCTIME length failed to match for rsa_time2: %lu, %lu\n", x, y);
      return 1;
   }
   DO(der_decode_utctime(buf[0], &y, &tmp_time));
   if (y != x || memcmp(&rsa_time2, &tmp_time, sizeof(ltc_utctime))) {
      fprintf(stderr, "UTCTIME decode failed for rsa_time2: %lu %lu\n", x, y);
fprintf(stderr, "\n\n%u %u %u %u %u %u %u %u %u\n\n", 
tmp_time.YY,
tmp_time.MM,
tmp_time.DD,
tmp_time.hh,
tmp_time.mm,
tmp_time.ss,
tmp_time.off_dir,
tmp_time.off_mm,
tmp_time.off_hh);


      return 1;
   }



   return der_choice_test();
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/testprof/der_tests.c,v $ */
/* $Revision: 1.25 $ */
/* $Date: 2005/06/20 20:37:45 $ */
