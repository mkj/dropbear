#include <mycrypt.h>

void reg_algs(void)
{
#ifdef RIJNDAEL
  register_cipher (&aes_desc);
#endif
#ifdef BLOWFISH
  register_cipher (&blowfish_desc);
#endif
#ifdef XTEA
  register_cipher (&xtea_desc);
#endif
#ifdef RC5
  register_cipher (&rc5_desc);
#endif
#ifdef RC6
  register_cipher (&rc6_desc);
#endif
#ifdef SAFERP
  register_cipher (&saferp_desc);
#endif
#ifdef TWOFISH
  register_cipher (&twofish_desc);
#endif
#ifdef SAFER
  register_cipher (&safer_k64_desc);
  register_cipher (&safer_sk64_desc);
  register_cipher (&safer_k128_desc);
  register_cipher (&safer_sk128_desc);
#endif
#ifdef RC2
  register_cipher (&rc2_desc);
#endif
#ifdef DES
  register_cipher (&des_desc);
  register_cipher (&des3_desc);
#endif
#ifdef CAST5
  register_cipher (&cast5_desc);
#endif
#ifdef NOEKEON
  register_cipher (&noekeon_desc);
#endif
#ifdef SKIPJACK
  register_cipher (&skipjack_desc);
#endif

#ifdef TIGER
  register_hash (&tiger_desc);
#endif
#ifdef MD2
  register_hash (&md2_desc);
#endif
#ifdef MD4
  register_hash (&md4_desc);
#endif
#ifdef MD5
  register_hash (&md5_desc);
#endif
#ifdef SHA1
  register_hash (&sha1_desc);
#endif
#ifdef SHA224
  register_hash (&sha224_desc);
#endif
#ifdef SHA256
  register_hash (&sha256_desc);
#endif
#ifdef SHA384
  register_hash (&sha384_desc);
#endif
#ifdef SHA512
  register_hash (&sha512_desc);
#endif
#ifdef RIPEMD128
  register_hash (&rmd128_desc);
#endif
#ifdef RIPEMD160
  register_hash (&rmd160_desc);
#endif
#ifdef WHIRLPOOL
  register_hash (&whirlpool_desc);
#endif
}

void hash_gen(void)
{
   unsigned char md[MAXBLOCKSIZE], buf[MAXBLOCKSIZE*2+2];
   unsigned long outlen, x, y, z;
   FILE *out;
   
   out = fopen("hash_tv.txt", "w");
   
   fprintf(out, "Hash Test Vectors:\n\nThese are the hashes of nn bytes '00 01 02 03 .. (nn-1)'\n\n");
   for (x = 0; hash_descriptor[x].name != NULL; x++) {
      fprintf(out, "Hash: %s\n", hash_descriptor[x].name);
      
      for (y = 0; y <= (hash_descriptor[x].blocksize * 2); y++) {
         for (z = 0; z < y; z++) {
            buf[z] = (unsigned char)(z & 255);
         }
         outlen = sizeof(md);
         hash_memory(x, buf, y, md, &outlen);
         fprintf(out, "%3lu: ", y);
         for (z = 0; z < outlen; z++) {
            fprintf(out, "%02X", md[z]);
         }
         fprintf(out, "\n");
      }
      fprintf(out, "\n");
   }
   fclose(out);
}

void cipher_gen(void)
{
   unsigned char key[MAXBLOCKSIZE], pt[MAXBLOCKSIZE];
   unsigned long x, y, z, w;
   int kl, lastkl;
   FILE *out;
   symmetric_key skey;
   
   out = fopen("cipher_tv.txt", "w");
   
   fprintf(out, 
"Cipher Test Vectors\n\nThese are test encryptions with key of nn bytes '00 01 02 03 .. (nn-1)' and original PT of the same style.\n"
"The output of step N is used as the key and plaintext for step N+1 (key bytes repeated as required to fill the key)\n\n");
                   
   for (x = 0; cipher_descriptor[x].name != NULL; x++) {
      fprintf(out, "Cipher: %s\n", cipher_descriptor[x].name);
      
      /* three modes, smallest, medium, large keys */
      lastkl = 10000;
      for (y = 0; y < 3; y++) {
         switch (y) {
            case 0: kl = cipher_descriptor[x].min_key_length; break;
            case 1: kl = (cipher_descriptor[x].min_key_length + cipher_descriptor[x].max_key_length)/2; break;
            case 2: kl = cipher_descriptor[x].max_key_length; break;
         }
         cipher_descriptor[x].keysize(&kl);
         if (kl == lastkl) break;
         lastkl = kl;
         fprintf(out, "Key Size: %d bytes\n", kl);

         for (z = 0; (int)z < kl; z++) {
             key[z] = (unsigned char)z;
         }
         cipher_descriptor[x].setup(key, kl, 0, &skey);
         
         for (z = 0; (int)z < cipher_descriptor[x].block_length; z++) {
            pt[z] = (unsigned char)z;
         }
         for (w = 0; w < 50; w++) {
             cipher_descriptor[x].ecb_encrypt(pt, pt, &skey);
             fprintf(out, "%2lu: ", w);
             for (z = 0; (int)z < cipher_descriptor[x].block_length; z++) {
                fprintf(out, "%02X", pt[z]);
             }
             fprintf(out, "\n");

             /* reschedule a new key */
             for (z = 0; z < (unsigned long)kl; z++) {
                 key[z] = pt[z % cipher_descriptor[x].block_length];
             }
             cipher_descriptor[x].setup(key, kl, 0, &skey);
         }
         fprintf(out, "\n");
     }
     fprintf(out, "\n");
  }
  fclose(out);
}  

void hmac_gen(void)
{
   unsigned char key[MAXBLOCKSIZE], output[MAXBLOCKSIZE], input[MAXBLOCKSIZE*2+2];
   int x, y, z, kl, err;
   FILE *out;
   unsigned long len;
  
   out = fopen("hmac_tv.txt", "w");

   fprintf(out, 
"HMAC Tests.  In these tests messages of N bytes long (00,01,02,...,NN-1) are HMACed.  The initial key is\n"
"of the same format (the same length as the HASH output size).  The HMAC key in step N+1 is the HMAC output of\n"
"step N.\n\n");

   for (x = 0; hash_descriptor[x].name != NULL; x++) {
      fprintf(out, "HMAC-%s\n", hash_descriptor[x].name);
      
      /* initial key */
      for (y = 0; y < (int)hash_descriptor[x].hashsize; y++) {
          key[y] = (y&255);
      }
      
      for (y = 0; y <= (int)(hash_descriptor[x].blocksize * 2); y++) {
         for (z = 0; z < y; z++) {
            input[z] = (unsigned char)(z & 255);
         }
         len = sizeof(output);
         if ((err = hmac_memory(x, key, hash_descriptor[x].hashsize, input, y, output, &len)) != CRYPT_OK) {
            printf("Error hmacing: %s\n", error_to_string(err));
            exit(EXIT_FAILURE);
         }
         fprintf(out, "%3d: ", y);
         for (z = 0; z <(int) len; z++) {
            fprintf(out, "%02X", output[z]);
         }
         fprintf(out, "\n");

         /* forward the key */
         memcpy(key, output, hash_descriptor[x].hashsize);
      }
      fprintf(out, "\n");
   }
   fclose(out);
}
   
void omac_gen(void)
{
   unsigned char key[MAXBLOCKSIZE], output[MAXBLOCKSIZE], input[MAXBLOCKSIZE*2+2];
   int err, x, y, z, kl;
   FILE *out;
   unsigned long len;
  
   out = fopen("omac_tv.txt", "w");

   fprintf(out, 
"OMAC Tests.  In these tests messages of N bytes long (00,01,02,...,NN-1) are OMAC'ed.  The initial key is\n"
"of the same format (length specified per cipher).  The OMAC key in step N+1 is the OMAC output of\n"
"step N (repeated as required to fill the array).\n\n");

   for (x = 0; cipher_descriptor[x].name != NULL; x++) {
      kl = cipher_descriptor[x].block_length;

      /* skip ciphers which do not have 64 or 128 bit block sizes */
      if (kl != 8 && kl != 16) continue;

      if (cipher_descriptor[x].keysize(&kl) != CRYPT_OK) {
         kl = cipher_descriptor[x].max_key_length;
      }
      fprintf(out, "OMAC-%s (%d byte key)\n", cipher_descriptor[x].name, kl);
      
      /* initial key/block */
      for (y = 0; y < kl; y++) {
          key[y] = (y & 255);
      }
      
      for (y = 0; y <= (int)(cipher_descriptor[x].block_length*2); y++) {
         for (z = 0; z < y; z++) {
            input[z] = (unsigned char)(z & 255);
         }
         len = sizeof(output);
         if ((err = omac_memory(x, key, kl, input, y, output, &len)) != CRYPT_OK) {
            printf("Error omacing: %s\n", error_to_string(err));
            exit(EXIT_FAILURE);
         }
         fprintf(out, "%3d: ", y);
         for (z = 0; z <(int)len; z++) {
            fprintf(out, "%02X", output[z]);
         }
         fprintf(out, "\n");

         /* forward the key */
         for (z = 0; z < kl; z++) {
             key[z] = output[z % len];
         }
      }
      fprintf(out, "\n");
   }
   fclose(out);
}

void pmac_gen(void)
{
   unsigned char key[MAXBLOCKSIZE], output[MAXBLOCKSIZE], input[MAXBLOCKSIZE*2+2];
   int err, x, y, z, kl;
   FILE *out;
   unsigned long len;
  
   out = fopen("pmac_tv.txt", "w");

   fprintf(out, 
"PMAC Tests.  In these tests messages of N bytes long (00,01,02,...,NN-1) are OMAC'ed.  The initial key is\n"
"of the same format (length specified per cipher).  The OMAC key in step N+1 is the OMAC output of\n"
"step N (repeated as required to fill the array).\n\n");

   for (x = 0; cipher_descriptor[x].name != NULL; x++) {
      kl = cipher_descriptor[x].block_length;

      /* skip ciphers which do not have 64 or 128 bit block sizes */
      if (kl != 8 && kl != 16) continue;

      if (cipher_descriptor[x].keysize(&kl) != CRYPT_OK) {
         kl = cipher_descriptor[x].max_key_length;
      }
      fprintf(out, "PMAC-%s (%d byte key)\n", cipher_descriptor[x].name, kl);
      
      /* initial key/block */
      for (y = 0; y < kl; y++) {
          key[y] = (y & 255);
      }
      
      for (y = 0; y <= (int)(cipher_descriptor[x].block_length*2); y++) {
         for (z = 0; z < y; z++) {
            input[z] = (unsigned char)(z & 255);
         }
         len = sizeof(output);
         if ((err = pmac_memory(x, key, kl, input, y, output, &len)) != CRYPT_OK) {
            printf("Error omacing: %s\n", error_to_string(err));
            exit(EXIT_FAILURE);
         }
         fprintf(out, "%3d: ", y);
         for (z = 0; z <(int)len; z++) {
            fprintf(out, "%02X", output[z]);
         }
         fprintf(out, "\n");

         /* forward the key */
         for (z = 0; z < kl; z++) {
             key[z] = output[z % len];
         }
      }
      fprintf(out, "\n");
   }
   fclose(out);
}

void eax_gen(void)
{
   int err, kl, x, y1, z;
   FILE *out;
   unsigned char key[MAXBLOCKSIZE], nonce[MAXBLOCKSIZE*2], header[MAXBLOCKSIZE*2], 
                 plaintext[MAXBLOCKSIZE*2], tag[MAXBLOCKSIZE];
   unsigned long len;

   out = fopen("eax_tv.txt", "w");
   fprintf(out, "EAX Test Vectors.  Uses the 00010203...NN-1 pattern for header/nonce/plaintext/key.  The outputs\n"
                "are of the form ciphertext,tag for a given NN.  The key for step N>1 is the tag of the previous\n"
                "step repeated sufficiently.\n\n");

   for (x = 0; cipher_descriptor[x].name != NULL; x++) {
      kl = cipher_descriptor[x].block_length;

      /* skip ciphers which do not have 64 or 128 bit block sizes */
      if (kl != 8 && kl != 16) continue;

      if (cipher_descriptor[x].keysize(&kl) != CRYPT_OK) {
         kl = cipher_descriptor[x].max_key_length;
      }
      fprintf(out, "EAX-%s (%d byte key)\n", cipher_descriptor[x].name, kl);

      /* the key */
      for (z = 0; z < kl; z++) {
          key[z] = (z & 255);
      }
      
      for (y1 = 0; y1 <= (int)(cipher_descriptor[x].block_length*2); y1++){
         for (z = 0; z < y1; z++) {
            plaintext[z] = (unsigned char)(z & 255);
            nonce[z]     = (unsigned char)(z & 255);
            header[z]    = (unsigned char)(z & 255);
         }
         len = sizeof(tag);
         if ((err = eax_encrypt_authenticate_memory(x, key, kl, nonce, y1, header, y1, plaintext, y1, plaintext, tag, &len)) != CRYPT_OK) {
            printf("Error EAX'ing: %s\n", error_to_string(err));
            exit(EXIT_FAILURE);
         }
         fprintf(out, "%3d: ", y1);
         for (z = 0; z < y1; z++) {
            fprintf(out, "%02X", plaintext[z]);
         }
         fprintf(out, ", ");
         for (z = 0; z <(int)len; z++) {
            fprintf(out, "%02X", tag[z]);
         }
         fprintf(out, "\n");

         /* forward the key */
         for (z = 0; z < kl; z++) {
             key[z] = tag[z % len];
         }
      }
      fprintf(out, "\n");
   }
   fclose(out);
}

void ocb_gen(void)
{
   int err, kl, x, y1, z;
   FILE *out;
   unsigned char key[MAXBLOCKSIZE], nonce[MAXBLOCKSIZE*2], 
                 plaintext[MAXBLOCKSIZE*2], tag[MAXBLOCKSIZE];
   unsigned long len;

   out = fopen("ocb_tv.txt", "w");
   fprintf(out, "OCB Test Vectors.  Uses the 00010203...NN-1 pattern for nonce/plaintext/key.  The outputs\n"
                "are of the form ciphertext,tag for a given NN.  The key for step N>1 is the tag of the previous\n"
                "step repeated sufficiently.  The nonce is fixed throughout.\n\n");

   for (x = 0; cipher_descriptor[x].name != NULL; x++) {
      kl = cipher_descriptor[x].block_length;

      /* skip ciphers which do not have 64 or 128 bit block sizes */
      if (kl != 8 && kl != 16) continue;

      if (cipher_descriptor[x].keysize(&kl) != CRYPT_OK) {
         kl = cipher_descriptor[x].max_key_length;
      }
      fprintf(out, "OCB-%s (%d byte key)\n", cipher_descriptor[x].name, kl);

      /* the key */
      for (z = 0; z < kl; z++) {
          key[z] = (z & 255);
      }

      /* fixed nonce */
      for (z = 0; z < cipher_descriptor[x].block_length; z++) {
          nonce[z] = z;
      }
      
      for (y1 = 0; y1 <= (int)(cipher_descriptor[x].block_length*2); y1++){
         for (z = 0; z < y1; z++) {
            plaintext[z] = (unsigned char)(z & 255);
         }
         len = sizeof(tag);
         if ((err = ocb_encrypt_authenticate_memory(x, key, kl, nonce, plaintext, y1, plaintext, tag, &len)) != CRYPT_OK) {
            printf("Error OCB'ing: %s\n", error_to_string(err));
            exit(EXIT_FAILURE);
         }
         fprintf(out, "%3d: ", y1);
         for (z = 0; z < y1; z++) {
            fprintf(out, "%02X", plaintext[z]);
         }
         fprintf(out, ", ");
         for (z = 0; z <(int)len; z++) {
            fprintf(out, "%02X", tag[z]);
         }
         fprintf(out, "\n");

         /* forward the key */
         for (z = 0; z < kl; z++) {
             key[z] = tag[z % len];
         }
      }
      fprintf(out, "\n");
   }
   fclose(out);
}

void base64_gen(void)
{
   FILE *out;
   unsigned char dst[256], src[32];
   unsigned long x, y, len;
   
   out = fopen("base64_tv.txt", "w");
   fprintf(out, "Base64 vectors.  These are the base64 encodings of the strings 00,01,02...NN-1\n\n");
   for (x = 0; x <= 32; x++) {
       for (y = 0; y < x; y++) {
           src[y] = y;
       }
       len = sizeof(dst);
       base64_encode(src, x, dst, &len);
       fprintf(out, "%2lu: %s\n", x, dst);
   }
   fclose(out);
}

int main(void)
{
   reg_algs();
   printf("Generating hash   vectors..."); fflush(stdout); hash_gen(); printf("done\n");
   printf("Generating cipher vectors..."); fflush(stdout); cipher_gen(); printf("done\n");
   printf("Generating HMAC   vectors..."); fflush(stdout); hmac_gen(); printf("done\n");
   printf("Generating OMAC   vectors..."); fflush(stdout); omac_gen(); printf("done\n");
   printf("Generating PMAC   vectors..."); fflush(stdout); pmac_gen(); printf("done\n");
   printf("Generating EAX    vectors..."); fflush(stdout); eax_gen(); printf("done\n");
   printf("Generating OCB    vectors..."); fflush(stdout); ocb_gen(); printf("done\n");
   printf("Generating BASE64 vectors..."); fflush(stdout); base64_gen(); printf("done\n");
   return 0;
}


         
      
      
      
    
   
