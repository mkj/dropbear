/* test CFB/OFB/CBC modes */
#include "test.h"

int modes_test(void)
{
   unsigned char pt[64], ct[64], tmp[64], key[16], iv[16];
   int x, cipher_idx;
   symmetric_CBC cbc;
   
   /* make a random pt, key and iv */
   yarrow_read(pt, 64,  &test_yarrow);
   yarrow_read(key, 16, &test_yarrow);
   yarrow_read(iv, 16,  &test_yarrow);
   
/* test CBC mode */
   cipher_idx = find_cipher("aes");
   if (cipher_idx == -1) {
      printf("test requires AES");
      return 1;
   }
   
   
   /* encode the block */
   DO(cbc_start(cipher_idx, iv, key, 16, 0, &cbc));
   for (x = 0; x < 4; x++) {
      DO(cbc_encrypt(pt+x*16, ct+x*16, &cbc));
   }
   
   /* decode the block */
   DO(cbc_start(cipher_idx, iv, key, 16, 0, &cbc));
   for (x = 0; x < 4; x++) {
      DO(cbc_decrypt(ct+x*16, tmp+x*16, &cbc));
   }
   if (memcmp(tmp, pt, 64) != 0) {
      printf("CBC failed");
      return 1;
   }
   
/*   
   extern int cbc_start(int cipher, const unsigned char *IV, const unsigned char *key,
                     int keylen, int num_rounds, symmetric_CBC *cbc);
extern int cbc_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_CBC *cbc);
extern int cbc_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_CBC *cbc);
*/

}
