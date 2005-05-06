#include <tomcrypt_test.h>

#ifdef MRSA 

#define RSA_MSGSIZE 78

int rsa_test(void)
{
   unsigned char in[1024], out[1024], tmp[1024];
   rsa_key       key, privKey, pubKey;
   int           hash_idx, prng_idx, stat, stat2, cnt;
   unsigned long rsa_msgsize, len, len2;
   static unsigned char lparam[] = { 0x01, 0x02, 0x03, 0x04 };
      
   hash_idx = find_hash("sha1");
   prng_idx = find_prng("yarrow");
   if (hash_idx == -1 || prng_idx == -1) {
      printf("rsa_test requires SHA1 and yarrow");
      return 1;
   }
   
   /* make 10 random key */
   for (cnt = 0; cnt < 10; cnt++) {
      DO(rsa_make_key(&yarrow_prng, prng_idx, 1024/8, 65537, &key));
      if (mp_count_bits(&key.N) != 1024) {
         printf("rsa_1024 key modulus has %d bits\n", mp_count_bits(&key.N));

len = mp_unsigned_bin_size(&key.N);
mp_to_unsigned_bin(&key.N, tmp);
printf("N == \n");
for (cnt = 0; cnt < len; ) {
   printf("%02x ", tmp[cnt]);
   if (!(++cnt & 15)) printf("\n");
}

len = mp_unsigned_bin_size(&key.p);
mp_to_unsigned_bin(&key.p, tmp);
printf("p == \n");
for (cnt = 0; cnt < len; ) {
   printf("%02x ", tmp[cnt]);
   if (!(++cnt & 15)) printf("\n");
}

len = mp_unsigned_bin_size(&key.q);
mp_to_unsigned_bin(&key.q, tmp);
printf("\nq == \n");
for (cnt = 0; cnt < len; ) {
   printf("%02x ", tmp[cnt]);
   if (!(++cnt & 15)) printf("\n");
}
printf("\n");


         return 1;
      }
      if (cnt != 9) {
         rsa_free(&key);
      }
   }
   
   /* test PKCS #1 v1.5 */
   for (cnt = 0; cnt < 4; cnt++) {
   for (rsa_msgsize = 1; rsa_msgsize <= 117; rsa_msgsize++) {
      /* make a random key/msg */
      yarrow_read(in, rsa_msgsize, &yarrow_prng);

      len  = sizeof(out);
      len2 = rsa_msgsize;

      /* encrypt */
      DO(rsa_v15_encrypt_key(in, rsa_msgsize, out, &len, &yarrow_prng, prng_idx, &key));
      DO(rsa_v15_decrypt_key(out, len, tmp, rsa_msgsize, &stat, &key));
      if (stat != 1 || memcmp(tmp, in, rsa_msgsize)) {
         printf("PKCS #1 v1.5 encrypt/decrypt failure (rsa_msgsize: %lu, stat: %d)\n", rsa_msgsize, stat);
         return 1;
      }
   }
   }

   /* signature */
   len = sizeof(out);
   DO(rsa_v15_sign_hash(in, 20, out, &len, hash_idx, &key));
   in[1] ^= 1;
   DO(rsa_v15_verify_hash(out, len, in, 20, hash_idx, &stat, &key));
   in[1] ^= 1;
   DO(rsa_v15_verify_hash(out, len, in, 20, hash_idx, &stat2, &key));
   if (!(stat == 0 && stat2 == 1)) {
      printf("PKCS #1 v1.5 sign/verify failure (stat %d, stat2 %d)\n", stat, stat2);
      return 1;
   }
   
   /* encrypt the key (without lparam) */
   for (cnt = 0; cnt < 4; cnt++) {
   for (rsa_msgsize = 1; rsa_msgsize <= 86; rsa_msgsize++) {
      /* make a random key/msg */
      yarrow_read(in, rsa_msgsize, &yarrow_prng);

      len  = sizeof(out);
      len2 = rsa_msgsize;
   
      DO(rsa_encrypt_key(in, rsa_msgsize, out, &len, NULL, 0, &yarrow_prng, prng_idx, hash_idx, &key));
      /* change a byte */
      out[8] ^= 1;
      DO(rsa_decrypt_key(out, len, tmp, &len2, NULL, 0, hash_idx, &stat2, &key));
      /* change a byte back */
      out[8] ^= 1;
      if (len2 != rsa_msgsize) {
         printf("\nrsa_decrypt_key mismatch len %lu (first decrypt)", len2);
         return 1;
      }

      len2 = rsa_msgsize;
      DO(rsa_decrypt_key(out, len, tmp, &len2, NULL, 0, hash_idx, &stat, &key));
      if (!(stat == 1 && stat2 == 0)) {
         printf("rsa_decrypt_key failed");
         return 1;
      }
      if (len2 != rsa_msgsize || memcmp(tmp, in, rsa_msgsize)) {
         unsigned long x;
         printf("\nrsa_decrypt_key mismatch, len %lu (second decrypt)\n", len2);
         printf("Original contents: \n"); 
         for (x = 0; x < rsa_msgsize; ) {
             printf("%02x ", in[x]);
             if (!(++x % 16)) {
                printf("\n");
             }
         }
         printf("\n");
         printf("Output contents: \n"); 
         for (x = 0; x < rsa_msgsize; ) {
             printf("%02x ", out[x]);
             if (!(++x % 16)) {
                printf("\n");
             }
         }     
         printf("\n");
         return 1;
      }
   }
   }

   /* encrypt the key (with lparam) */
   for (rsa_msgsize = 1; rsa_msgsize <= 86; rsa_msgsize++) {
      len  = sizeof(out);
      len2 = rsa_msgsize;
      DO(rsa_encrypt_key(in, rsa_msgsize, out, &len, lparam, sizeof(lparam), &yarrow_prng, prng_idx, hash_idx, &key));
      /* change a byte */
      out[8] ^= 1;
      DO(rsa_decrypt_key(out, len, tmp, &len2, lparam, sizeof(lparam), hash_idx, &stat2, &key));
      if (len2 != rsa_msgsize) {
         printf("\nrsa_decrypt_key mismatch len %lu (first decrypt)", len2);
         return 1;
      }
      /* change a byte back */
      out[8] ^= 1;

      len2 = rsa_msgsize;
      DO(rsa_decrypt_key(out, len, tmp, &len2, lparam, sizeof(lparam), hash_idx, &stat, &key));
      if (!(stat == 1 && stat2 == 0)) {
         printf("rsa_decrypt_key failed");
         return 1;
      }
      if (len2 != rsa_msgsize || memcmp(tmp, in, rsa_msgsize)) {
         printf("rsa_decrypt_key mismatch len %lu", len2);
         return 1;
      }
   }

   /* sign a message (unsalted, lower cholestorol and Atkins approved) now */
   len = sizeof(out);
   DO(rsa_sign_hash(in, 20, out, &len, &yarrow_prng, prng_idx, hash_idx, 0, &key));

/* export key and import as both private and public */
   len2 = sizeof(tmp);
   DO(rsa_export(tmp, &len2, PK_PRIVATE, &key)); 
   DO(rsa_import(tmp, len2, &privKey)); 
   len2 = sizeof(tmp);
   DO(rsa_export(tmp, &len2, PK_PUBLIC, &key));
   DO(rsa_import(tmp, len2, &pubKey));

   /* verify with original */
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat, &key));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat2, &key));
   
   if (!(stat == 1 && stat2 == 0)) {
      printf("rsa_verify_hash (unsalted, origKey) failed, %d, %d", stat, stat2);
      rsa_free(&key);
      rsa_free(&pubKey);
      rsa_free(&privKey);
      return 1;
   }

   /* verify with privKey */
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat, &privKey));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat2, &privKey));
   
   if (!(stat == 1 && stat2 == 0)) {
      printf("rsa_verify_hash (unsalted, privKey) failed, %d, %d", stat, stat2);
      rsa_free(&key);
      rsa_free(&pubKey);
      rsa_free(&privKey);
      return 1;
   }

   /* verify with pubKey */
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat, &pubKey));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 0, &stat2, &pubKey));
   
   if (!(stat == 1 && stat2 == 0)) {
      printf("rsa_verify_hash (unsalted, pubkey) failed, %d, %d", stat, stat2);
      rsa_free(&key);
      rsa_free(&pubKey);
      rsa_free(&privKey);
      return 1;
   }

   /* sign a message (salted) now (use privKey to make, pubKey to verify) */
   len = sizeof(out);
   DO(rsa_sign_hash(in, 20, out, &len, &yarrow_prng, prng_idx, hash_idx, 8, &privKey));
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 8, &stat, &pubKey));
   /* change a byte */
   in[0] ^= 1;
   DO(rsa_verify_hash(out, len, in, 20, hash_idx, 8, &stat2, &pubKey));
   
   if (!(stat == 1 && stat2 == 0)) {
      printf("rsa_verify_hash (salted) failed, %d, %d", stat, stat2);
      rsa_free(&key);
      rsa_free(&pubKey);
      rsa_free(&privKey);
      return 1;
   }
   
   /* free the key and return */
   rsa_free(&key);
   rsa_free(&pubKey);
   rsa_free(&privKey);
   return 0;
}

#else

int rsa_test(void)
{
   printf("NOP");
   return 0;
}

#endif
