#include "test.h"

int rsa_test(void)
{
   unsigned char in[1024], out[1024], tmp[1024];
   rsa_key       key;
   int           hash_idx, prng_idx, stat, stat2;
   unsigned long len, len2;
   static unsigned char lparam[] = { 0x01, 0x02, 0x03, 0x04 };
      
   hash_idx = find_hash("sha1");
   prng_idx = find_prng("yarrow");
   if (hash_idx == -1 || prng_idx == -1) {
      printf("rsa_test requires SHA1 and yarrow");
      return 1;
   }
   
   /* make a random key/msg */
   yarrow_read(in, 20, &test_yarrow);
   
   /* make a random key */
   DO(rsa_make_key(&test_yarrow, prng_idx, 1024/8, 65537, &key));
   
   /* encrypt the key (without lparam) */
   len  = sizeof(out);
   len2 = sizeof(tmp);
   DO(rsa_encrypt_key(in, 20, out, &len, NULL, 0, &test_yarrow, prng_idx, hash_idx, &key));
   /* change a byte */
   out[0] ^= 1;
   DO(rsa_decrypt_key(out, len, tmp, &len2, NULL, 0, &test_yarrow, prng_idx, hash_idx, &stat2, &key));
   /* change a byte back */
   out[0] ^= 1;
   DO(rsa_decrypt_key(out, len, tmp, &len2, NULL, 0, &test_yarrow, prng_idx, hash_idx, &stat, &key));
   if (!(stat == 1 && stat2 == 0)) {
      printf("rsa_decrypt_key failed");
      return 1;
   }
   if (len2 != 20 || memcmp(tmp, in, 20)) {
      printf("rsa_decrypt_key mismatch len %lu", len2);
      return 1;
   }

   /* encrypt the key (with lparam) */
   len  = sizeof(out);
   len2 = sizeof(tmp);
   DO(rsa_encrypt_key(in, 20, out, &len, lparam, sizeof(lparam), &test_yarrow, prng_idx, hash_idx, &key));
   /* change a byte */
   out[0] ^= 1;
   DO(rsa_decrypt_key(out, len, tmp, &len2, lparam, sizeof(lparam), &test_yarrow, prng_idx, hash_idx, &stat2, &key));
   /* change a byte back */
   out[0] ^= 1;
   DO(rsa_decrypt_key(out, len, tmp, &len2, lparam, sizeof(lparam), &test_yarrow, prng_idx, hash_idx, &stat, &key));
   if (!(stat == 1 && stat2 == 0)) {
      printf("rsa_decrypt_key failed");
      return 1;
   }
   if (len2 != 20 || memcmp(tmp, in, 20)) {
      printf("rsa_decrypt_key mismatch len %lu", len2);
      return 1;
   }

   /* sign a message (unsalted, lower cholestorol and Atkins approved) now */
   len = sizeof(out);
   DO(rsa_sign_hash(in, 20, out, &len, &test_yarrow, prng_idx, hash_idx, 0, &key));
   DO(rsa_verify_hash(out, len, in, 20, &test_yarrow, prng_idx, hash_idx, 0, &stat, &key));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, &test_yarrow, prng_idx, hash_idx, 0, &stat2, &key));
   
   if (!(stat == 1 && stat2 == 0)) {
      printf("rsa_verify_hash (unsalted) failed, %d, %d", stat, stat2);
      return 1;
   }

   /* sign a message (salted) now */
   len = sizeof(out);
   DO(rsa_sign_hash(in, 20, out, &len, &test_yarrow, prng_idx, hash_idx, 8, &key));
   DO(rsa_verify_hash(out, len, in, 20, &test_yarrow, prng_idx, hash_idx, 8, &stat, &key));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, &test_yarrow, prng_idx, hash_idx, 8, &stat2, &key));
   
   if (!(stat == 1 && stat2 == 0)) {
      printf("rsa_verify_hash (salted) failed, %d, %d", stat, stat2);
      return 1;
   }
   
   /* free the key and return */
   rsa_free(&key);
   return 0;
}
