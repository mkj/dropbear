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
#ifdef SHA256
  register_hash (&sha256_desc);
#endif
#ifdef SHA384
  register_hash (&sha384_desc);
#endif
#ifdef SHA512
  register_hash (&sha512_desc);
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
            buf[z] = (unsigned char)z;
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
   
   fprintf(out, "Cipher Test Vectors\n\nThese are test encryptions with key of nn bytes '00 01 02 03 .. (nn-1)' and original PT of the same style.\n\n");
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
         for (w = 0; w < 25; w++) {
             cipher_descriptor[x].ecb_encrypt(pt, pt, &skey);
             fprintf(out, "%2lu: ", w);
             for (z = 0; (int)z < cipher_descriptor[x].block_length; z++) {
                fprintf(out, "%02X", pt[z]);
             }
             fprintf(out, "\n");
         }
         fprintf(out, "\n");
     }
     fprintf(out, "\n");
  }
  fclose(out);
}  
   

int main(void)
{
   reg_algs();
   hash_gen();
   cipher_gen();
   
   return 0;
}


         
      
      
      
    
   
