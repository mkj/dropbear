/* test the ciphers and hashes using their built-in self-tests */

#include "test.h"

int cipher_hash_test(void)
{
   int x;
   
   /* test ciphers */
   for (x = 0; cipher_descriptor[x].name != NULL; x++) {
      DO(cipher_descriptor[x].test());
   }
   
   /* test hashes */
   for (x = 0; hash_descriptor[x].name != NULL; x++) {
      DO(hash_descriptor[x].test());
   }
   
   return 0;
}
