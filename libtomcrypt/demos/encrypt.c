/* encrypt V1.1 Fri Oct 18 04:28:03 NZDT 2002 */
/* File de/encryption, using libtomcrypt */
/* Written by Daniel Richards <kyhwana@world-net.co.nz> */
/* Help from Tom St Denis with various bits */
/* This code is public domain, no rights reserved. */
/* Encrypts by default, -d flag enables decryption */
/* ie: ./encrypt blowfish story.txt story.ct */
/* ./encrypt -d blowfish story.ct story.pt */

#include <mycrypt.h>

int errno;

static const struct _cipher_descriptor *ciphers[] = {
   &blowfish_desc,   &xtea_desc,        &rc5_desc,        &rc6_desc,
   &saferp_desc,     &serpent_desc,     &rijndael_desc,
   &twofish_desc,    &safer_k64_desc,   &safer_sk64_desc,
   &safer_k128_desc, &safer_sk128_desc, &rc2_desc,
   &des_desc,        &des3_desc,        &cast5_desc, NULL
};

int usage(void) 
{
   int x;

   printf("Usage: ./crypt [-d](ecrypt) cipher infile outfile\nCiphers:\n");
   for (x = 0; cipher_descriptor[x].name != NULL; x++) {
      printf("%s\n",cipher_descriptor[x].name);
   }
   exit(1);
}

void register_algs(void)
{
   int x;
   
   for (x = 0; ciphers[x] != NULL; x++) {
       if (register_cipher(ciphers[x]) == -1) {
          printf("Error registering cipher\n");
          exit(-1);
       }
   }

   if (register_hash(&sha256_desc) == -1) {
      printf("Error registering SHA256\n");
      exit(-1);
   } 

   if (register_prng(&yarrow_desc) == -1) {
      printf("Error registering yarrow PRNG\n");
      exit(-1);
   }

   if (register_prng(&sprng_desc) == -1) {
      printf("Error registering sprng PRNG\n");
      exit(-1);
   }
}

int main(int argc, char *argv[]) 
{
   unsigned char plaintext[512],ciphertext[512];
   unsigned char tmpkey[512], key[MAXBLOCKSIZE], IV[MAXBLOCKSIZE];
   unsigned char inbuf[512]; /* i/o block size */
   unsigned long outlen, y, ivsize, x, decrypt;
   symmetric_CTR ctr;
   int cipher_idx, hash_idx, ks;
   char *infile, *outfile, *cipher;
   prng_state prng;
   FILE *fdin, *fdout;

   /* register algs, so they can be printed */
   register_algs();

   if (argc < 4) {
      return usage();
   }

   if (!strcmp(argv[1], "-d")) {
      decrypt = 1;
      cipher  = argv[2];
      infile  = argv[3];
      outfile = argv[4];
   } else {
      decrypt = 0;
      cipher  = argv[1];
      infile  = argv[2];
      outfile = argv[3];
   }   

   /* file handles setup */
   fdin = fopen(infile,"rb");
   if (fdin == NULL) {
      perror("Can't open input for reading");
      exit(-1);
   }

   fdout = fopen(outfile,"wb");
   if (fdout == NULL) { 
      perror("Can't open output for writing");
      exit(-1);
   }
 
   cipher_idx = find_cipher(cipher);
   if (cipher_idx == -1) {
      printf("Invalid cipher entered on command line.\n");
      exit(-1);
   }

   hash_idx = find_hash("sha256");
   if (hash_idx == -1) {
      printf("SHA256 not found...?\n");
      exit(-1);
   }

   ivsize = cipher_descriptor[cipher_idx].block_length;
   ks = hash_descriptor[hash_idx].hashsize;
   if (cipher_descriptor[cipher_idx].keysize(&ks) != CRYPT_OK) { 
      printf("Invalid keysize???\n");
      exit(-1);
   }

   printf("\nEnter key: ");
   fgets(tmpkey,sizeof(tmpkey), stdin);
   outlen = sizeof(key);
   if ((errno = hash_memory(hash_idx,tmpkey,strlen(tmpkey),key,&outlen)) != CRYPT_OK) {
      printf("Error hashing key: %s\n", error_to_string(errno));
      exit(-1);
   }
   
   if (decrypt) {
      /* Need to read in IV */
      if (fread(IV,1,ivsize,fdin) != ivsize) {
         printf("Error reading IV from input.\n");
         exit(-1);
      }
   
      if ((errno = ctr_start(cipher_idx,IV,key,ks,0,&ctr)) != CRYPT_OK) {
         printf("ctr_start error: %s\n",error_to_string(errno));
         exit(-1);
      }

      /* IV done */
      do {
         y = fread(inbuf,1,sizeof(inbuf),fdin);

         if ((errno = ctr_decrypt(inbuf,plaintext,y,&ctr)) != CRYPT_OK) {
            printf("ctr_decrypt error: %s\n", error_to_string(errno));
            exit(-1);
         }

         if (fwrite(plaintext,1,y,fdout) != y) {
            printf("Error writing to file.\n");
            exit(-1);
         }
      } while (y == sizeof(inbuf));
      fclose(fdin);
      fclose(fdout);

   } else {  /* encrypt */
      /* Setup yarrow for random bytes for IV */
      
      if ((errno = rng_make_prng(128, find_prng("yarrow"), &prng, NULL)) != CRYPT_OK) {
         printf("Error setting up PRNG, %s\n", error_to_string(errno));
      }      

      /* You can use rng_get_bytes on platforms that support it */
      /* x = rng_get_bytes(IV,ivsize,NULL);*/
      x = yarrow_read(IV,ivsize,&prng);
      if (x != ivsize) {
         printf("Error reading PRNG for IV required.\n");
         exit(-1);
      }
   
      if (fwrite(IV,1,ivsize,fdout) != ivsize) {
         printf("Error writing IV to output.\n");
         exit(-1);
      }

      if ((errno = ctr_start(cipher_idx,IV,key,ks,0,&ctr)) != CRYPT_OK) {
         printf("ctr_start error: %s\n",error_to_string(errno));
         exit(-1);
      }

      do {
         y = fread(inbuf,1,sizeof(inbuf),fdin);

         if ((errno = ctr_encrypt(inbuf,ciphertext,y,&ctr)) != CRYPT_OK) {
            printf("ctr_encrypt error: %s\n", error_to_string(errno));
            exit(-1);
         }

         if (fwrite(ciphertext,1,y,fdout) != y) {
            printf("Error writing to output.\n");
            exit(-1);
         }
      } while (y == sizeof(inbuf));   
      fclose(fdout);
      fclose(fdin);
   }
   return 0;
}
