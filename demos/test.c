#include <tomcrypt_test.h>

int main(void)
{
   reg_algs();
   printf("build == \n%s\n", crypt_build_settings);
   printf("\ncipher_test..."); fflush(stdout); printf(cipher_hash_test() ? "failed" : "passed");
   printf("\nmodes_test..."); fflush(stdout); printf(modes_test() ? "failed" : "passed");
   printf("\nmac_test..."); fflush(stdout); printf(mac_test() ? "failed" : "passed");
   printf("\npkcs_1_test..."); fflush(stdout); printf(pkcs_1_test() ? "failed" : "passed");
   printf("\nstore_test..."); fflush(stdout); printf(store_test() ? "failed" : "passed");
   printf("\nrsa_test..."); fflush(stdout); printf(rsa_test() ? "failed" : "passed");
   printf("\necc_test..."); fflush(stdout); printf(ecc_tests() ? "failed" : "passed");
   printf("\ndsa_test..."); fflush(stdout); printf(dsa_test() ? "failed" : "passed");
   printf("\ndh_test..."); fflush(stdout); printf(dh_tests() ? "failed" : "passed");
   printf("\nder_test..."); fflush(stdout); printf(der_tests() ? "failed" : "passed");

   return EXIT_SUCCESS;
}
