/* test CFB/OFB/CBC modes */
#include "test.h"

int modes_test(void)
{
   unsigned char pt[64], ct[64], tmp[64], key[16], iv[16], iv2[16];
   int x, cipher_idx;
   symmetric_CBC cbc;
   symmetric_CFB cfb;
   symmetric_OFB ofb;
   symmetric_CTR ctr;
   unsigned long l;
   
   /* make a random pt, key and iv */
   yarrow_read(pt,  64, &test_yarrow);
   yarrow_read(key, 16, &test_yarrow);
   yarrow_read(iv,  16, &test_yarrow);
   
   /* get idx of AES handy */
   cipher_idx = find_cipher("aes");
   if (cipher_idx == -1) {
      printf("test requires AES");
      return 1;
   }
   
   /* test CBC mode */
   /* encode the block */
   DO(cbc_start(cipher_idx, iv, key, 16, 0, &cbc));
   l = sizeof(iv2);
   DO(cbc_getiv(iv2, &l, &cbc));
   if (l != 16 || memcmp(iv2, iv, 16)) {
      printf("cbc_getiv failed");
      return 1;
   }
   for (x = 0; x < 4; x++) {
      DO(cbc_encrypt(pt+x*16, ct+x*16, &cbc));
   }
   
   /* decode the block */
   DO(cbc_setiv(iv2, l, &cbc));
   zeromem(tmp, sizeof(tmp));
   for (x = 0; x < 4; x++) {
      DO(cbc_decrypt(ct+x*16, tmp+x*16, &cbc));
   }
   if (memcmp(tmp, pt, 64) != 0) {
      printf("CBC failed");
      return 1;
   }
   
   /* test CFB mode */
   /* encode the block */
   DO(cfb_start(cipher_idx, iv, key, 16, 0, &cfb));
   l = sizeof(iv2);
   DO(cfb_getiv(iv2, &l, &cfb));
   /* note we don't memcmp iv2/iv since cfb_start processes the IV for the first block */
   if (l != 16) {
      printf("cfb_getiv failed");
      return 1;
   }
   DO(cfb_encrypt(pt, ct, 64, &cfb));
   
   /* decode the block */
   DO(cfb_setiv(iv, l, &cfb));
   zeromem(tmp, sizeof(tmp));
   DO(cfb_decrypt(ct, tmp, 64, &cfb));
   if (memcmp(tmp, pt, 64) != 0) {
      printf("CFB failed");
      return 1;
   }
   
   /* test OFB mode */
   /* encode the block */
   DO(ofb_start(cipher_idx, iv, key, 16, 0, &ofb));
   l = sizeof(iv2);
   DO(ofb_getiv(iv2, &l, &ofb));
   if (l != 16 || memcmp(iv2, iv, 16)) {
      printf("ofb_getiv failed");
      return 1;
   }
   DO(ofb_encrypt(pt, ct, 64, &ofb));
   
   /* decode the block */
   DO(ofb_setiv(iv2, l, &ofb));
   zeromem(tmp, sizeof(tmp));
   DO(ofb_decrypt(ct, tmp, 64, &ofb));
   if (memcmp(tmp, pt, 64) != 0) {
      printf("OFB failed");
      return 1;
   }
   
   /* test CTR mode */
   /* encode the block */
   DO(ctr_start(cipher_idx, iv, key, 16, 0, &ctr));
   l = sizeof(iv2);
   DO(ctr_getiv(iv2, &l, &ctr));
   if (l != 16 || memcmp(iv2, iv, 16)) {
      printf("ctr_getiv failed");
      return 1;
   }
   DO(ctr_encrypt(pt, ct, 64, &ctr));
   
   /* decode the block */
   DO(ctr_setiv(iv2, l, &ctr));
   zeromem(tmp, sizeof(tmp));
   DO(ctr_decrypt(ct, tmp, 64, &ctr));
   if (memcmp(tmp, pt, 64) != 0) {
      printf("CTR failed");
      return 1;
   }
         
   return 0;
}
