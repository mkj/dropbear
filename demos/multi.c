/* test the multi helpers... */
#include <tomcrypt.h>

int main(void)
{
   unsigned char key[16], buf[2][MAXBLOCKSIZE];
   unsigned long len, len2;


/* register algos */
   register_hash(&sha256_desc);
   register_cipher(&aes_desc);

/* HASH testing */
   len = sizeof(buf[0]);
   hash_memory(find_hash("sha256"), "hello", 5, buf[0], &len);
   len2 = sizeof(buf[0]);
   hash_memory_multi(find_hash("sha256"), buf[1], &len2, "hello", 5, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }
   len2 = sizeof(buf[0]);
   hash_memory_multi(find_hash("sha256"), buf[1], &len2, "he", 2, "llo", 3, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }
   len2 = sizeof(buf[0]);
   hash_memory_multi(find_hash("sha256"), buf[1], &len2, "h", 1, "e", 1, "l", 1, "l", 1, "o", 1, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }

/* HMAC */
   len = sizeof(buf[0]);
   hmac_memory(find_hash("sha256"), key, 16, "hello", 5, buf[0], &len);
   len2 = sizeof(buf[0]);
   hmac_memory_multi(find_hash("sha256"), key, 16, buf[1], &len2, "hello", 5, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }
   len2 = sizeof(buf[0]);
   hmac_memory_multi(find_hash("sha256"), key, 16, buf[1], &len2, "he", 2, "llo", 3, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }
   len2 = sizeof(buf[0]);
   hmac_memory_multi(find_hash("sha256"), key, 16, buf[1], &len2, "h", 1, "e", 1, "l", 1, "l", 1, "o", 1, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }

/* OMAC */
   len = sizeof(buf[0]);
   omac_memory(find_cipher("aes"), key, 16, "hello", 5, buf[0], &len);
   len2 = sizeof(buf[0]);
   omac_memory_multi(find_cipher("aes"), key, 16, buf[1], &len2, "hello", 5, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }
   len2 = sizeof(buf[0]);
   omac_memory_multi(find_cipher("aes"), key, 16, buf[1], &len2, "he", 2, "llo", 3, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }
   len2 = sizeof(buf[0]);
   omac_memory_multi(find_cipher("aes"), key, 16, buf[1], &len2, "h", 1, "e", 1, "l", 1, "l", 1, "o", 1, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }

/* PMAC */
   len = sizeof(buf[0]);
   pmac_memory(find_cipher("aes"), key, 16, "hello", 5, buf[0], &len);
   len2 = sizeof(buf[0]);
   pmac_memory_multi(find_cipher("aes"), key, 16, buf[1], &len2, "hello", 5, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }
   len2 = sizeof(buf[0]);
   pmac_memory_multi(find_cipher("aes"), key, 16, buf[1], &len2, "he", 2, "llo", 3, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }
   len2 = sizeof(buf[0]);
   pmac_memory_multi(find_cipher("aes"), key, 16, buf[1], &len2, "h", 1, "e", 1, "l", 1, "l", 1, "o", 1, NULL);
   if (len != len2 || memcmp(buf[0], buf[1], len)) {
      printf("Failed: %d %lu %lu\n", __LINE__, len, len2);
      return EXIT_FAILURE;
   }


   printf("All passed\n");
   return EXIT_SUCCESS;
}

