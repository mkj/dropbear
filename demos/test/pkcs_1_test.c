#include "test.h"

int pkcs_1_test(void)
{
   unsigned char buf[3][128];
   int res1, res2, res3, prng_idx, hash_idx;
   unsigned long x, y, l1, l2, l3, i1, i2, lparamlen, saltlen, modlen;
   static const unsigned char lparam[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };

   /* get hash/prng  */
   hash_idx = find_hash("sha1");
   prng_idx = find_prng("yarrow");
   
   if (hash_idx == -1 || prng_idx == -1) {
      printf("pkcs_1 tests require sha1/yarrow");
      return 1;
   }   

   /* do many tests */
   for (x = 0; x < 10000; x++) {
      zeromem(buf, sizeof(buf));

      /* make a dummy message (of random length) */
      l3 = (rand() & 31) + 8;
      for (y = 0; y < l3; y++) buf[0][y] = rand() & 255;

      /* random modulus len (v1.5 must be multiple of 8 though arbitrary sizes seem to work) */
      modlen = 800 + 8 * (abs(rand()) % 28);

      /* PKCS v1.5 testing (encryption) */
      l1 = sizeof(buf[1]);
      DO(pkcs_1_v15_es_encode(buf[0], l3, modlen, &test_yarrow, prng_idx, buf[1], &l1));
      DO(pkcs_1_v15_es_decode(buf[1], l1, modlen, buf[2], l3, &res1));
      if (res1 != 1 || memcmp(buf[0], buf[2], l3)) {
         printf("pkcs v1.5 encrypt failed %d, %lu, %lu ", res1, l1, l3);
         return 1;
      }

      /* PKCS v1.5 testing (signatures) */
      l1 = sizeof(buf[1]);
      DO(pkcs_1_v15_sa_encode(buf[0], l3, hash_idx, modlen, buf[1], &l1));
      DO(pkcs_1_v15_sa_decode(buf[0], l3, buf[1], l1, hash_idx, modlen, &res1));
      buf[0][i1 = abs(rand()) % l3] ^= 1;
      DO(pkcs_1_v15_sa_decode(buf[0], l3, buf[1], l1, hash_idx, modlen, &res2));
      buf[0][i1] ^= 1;
      buf[1][i2 = abs(rand()) % l1] ^= 1;
      DO(pkcs_1_v15_sa_decode(buf[0], l3, buf[1], l1, hash_idx, modlen, &res3));

      if (!(res1 == 1 && res2 == 0 && res3 == 0)) {
         printf("pkcs v1.5 sign failed %d %d %d ", res1, res2, res3);
         return 1;
      }

      /* pick a random lparam len [0..16] */
      lparamlen = abs(rand()) % 17;

      /* pick a random saltlen 0..16 */
      saltlen   = abs(rand()) % 17;

      /* PKCS #1 v2.0 supports modlens not multiple of 8 */
      modlen = 800 + (abs(rand()) % 224);

      /* encode it */
      l1 = sizeof(buf[1]);
      DO(pkcs_1_oaep_encode(buf[0], l3, lparam, lparamlen, modlen, &test_yarrow, prng_idx, hash_idx, buf[1], &l1));

      /* decode it */
      l2 = sizeof(buf[2]);
      DO(pkcs_1_oaep_decode(buf[1], l1, lparam, lparamlen, modlen, hash_idx, buf[2], &l2, &res1));

      if (res1 != 1 || l2 != l3 || memcmp(buf[2], buf[0], l3) != 0) {
         printf("Outsize == %lu, should have been %lu, res1 = %d, lparamlen = %lu, msg contents follow.\n", l2, l3, res1, lparamlen);
         printf("ORIGINAL:\n");
         for (x = 0; x < l3; x++) {
             printf("%02x ", buf[0][x]);
         }
         printf("\nRESULT:\n");
         for (x = 0; x < l2; x++) {
             printf("%02x ", buf[2][x]);
         }
         printf("\n\n");
         return 1;
      }

      /* test PSS */
      l1 = sizeof(buf[1]);
      DO(pkcs_1_pss_encode(buf[0], l3, saltlen, &test_yarrow, prng_idx, hash_idx, modlen, buf[1], &l1));
      DO(pkcs_1_pss_decode(buf[0], l3, buf[1], l1, saltlen, hash_idx, modlen, &res1));
      
      buf[0][i1 = abs(rand()) % l3] ^= 1;
      DO(pkcs_1_pss_decode(buf[0], l3, buf[1], l1, saltlen, hash_idx, modlen, &res2));

      buf[0][i1] ^= 1;
      buf[1][i2 = abs(rand()) % l1] ^= 1;
      DO(pkcs_1_pss_decode(buf[0], l3, buf[1], l1, saltlen, hash_idx, modlen, &res3));

      if (!(res1 == 1 && res2 == 0 && res3 == 0)) {
         printf("PSS failed: %d, %d, %d, %lu, %lu\n", res1, res2, res3, l3, saltlen);
         return 1;
      }
   }
   return 0;
}
