#include "test.h"

test_entry tests[26];

test_entry test_list[26] = { 

/* test name          provides    requires             entry */
{"store_test",             "a",         "",          store_test           },
{"cipher_hash_test",       "b",        "a",          cipher_hash_test     },
{"modes_test",             "c",        "b",          modes_test           },
{"mac_test",               "d",        "c",          mac_test             },
{"der_test",               "e",         "",          der_tests            },

{"pkcs_1_test",            "f",        "e",          pkcs_1_test          },
{"rsa_test",               "g",        "e",          rsa_test             },
{"ecc_test",               "h",        "a",          ecc_tests            },
{"dsa_test",               "i",        "a",          dsa_test             },
{"dh_test",                "j",        "a",          dh_tests             },

{NULL, NULL, NULL, NULL} 
};

prng_state test_yarrow;
static int current_test;

void run_cmd(int res, int line, char *file, char *cmd)
{
   if (res != CRYPT_OK) {
      fprintf(stderr, "[%s]: %s (%d)\n%s:%d:%s\n", tests[current_test].name, error_to_string(res), res, file, line, cmd);
      exit(EXIT_FAILURE);
   }
}

void register_algs(void)
{
  int err;

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
#ifdef SHA256
  register_hash (&sha256_desc);
#endif
#ifdef SHA224
  register_hash (&sha224_desc);
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
#ifdef CHC_HASH
  register_hash(&chc_desc);
  if ((err = chc_register(register_cipher(&aes_enc_desc))) != CRYPT_OK) {
     printf("chc_register error: %s\n", error_to_string(err));
     exit(EXIT_FAILURE);
  }
#endif


#ifdef YARROW
   register_prng(&yarrow_desc);
#endif
#ifdef FORTUNA
   register_prng(&fortuna_desc);
#endif
#ifdef RC4
   register_prng(&rc4_desc);
#endif
#ifdef SPRNG
   register_prng(&sprng_desc);
#endif
#ifdef SOBER128
   register_prng(&sober128_desc);
#endif
}

/* sort tests based on their requirement/services.  Helps make sure dependencies are tested first */
void sort(void)
{
   unsigned x, y, z, a, pidx[26];
      
   /* find out where things are provided */
   zeromem(pidx, sizeof(pidx));   
   z = 0;
   do { 
      y = 0;
      for (x = 0; test_list[x].name != NULL; x++) {
        if (test_list[x].entry == NULL) continue;
        if (strlen(test_list[x].prov) == 0) {
           y = 1;
           tests[z++] = test_list[x]; test_list[x].entry = NULL;
           pidx[test_list[x].prov[0]-'a'] = 1;
           break;
        } else {
           for (a = 0; a < strlen(test_list[x].req); a++) {
               if (pidx[test_list[x].req[a]-'a'] == 0) break;
           }
           if (a == strlen(test_list[x].req)) {
              y = 1;
              tests[z++] = test_list[x]; test_list[x].entry = NULL;
              pidx[test_list[x].prov[0]-'a'] = 1;
              break;
           }
        }
      }
   } while (y == 1);
}

#define STACKBLOCK       8
#define STACK_EST_USAGE  32768

unsigned char stack_mask[STACKBLOCK];
unsigned long stack_cur=0;

void stack_masker(void)
{
#ifdef STACK_TEST
   volatile unsigned char M[STACK_EST_USAGE];
   stack_cur   = 0;
   for (stack_cur = 0; stack_cur < STACK_EST_USAGE/STACKBLOCK; stack_cur++) {
       memcpy(M+(stack_cur*STACKBLOCK), stack_mask, STACKBLOCK);
   }
#endif
}

void stack_check(void)
{
#ifdef STACK_TEST
   unsigned char M[STACK_EST_USAGE];
   stack_cur   = 0;
#ifdef STACK_DOWN
   while (memcmp(M+(STACK_EST_USAGE-STACKBLOCK-stack_cur), stack_mask, STACKBLOCK) && 
#else
   while (memcmp(M+stack_cur, stack_mask, STACKBLOCK) &&
#endif
          stack_cur < (STACK_EST_USAGE - STACKBLOCK)) {
      ++stack_cur;
   }
#endif
}

int main(void)
{
   int x;
   unsigned char buf[16];

   /* setup stack checker */
   srand(time(NULL));
   for (x = 0; x < STACKBLOCK; x++) {
       stack_mask[x] = rand() & 255;
   }
   stack_masker();

   printf("Built with\n%s\n", crypt_build_settings);

   sort();
   register_algs();
      
   // start dummy yarrow for internal use 
   DO(yarrow_start(&test_yarrow));
   sprng_read(buf, 16, NULL);
   DO(yarrow_add_entropy(buf, 16, &test_yarrow));
   DO(yarrow_ready(&test_yarrow));

   // output sizes 
   printf("Sizes of objects (in bytes)\n");
   printf("\tsymmetric_key\t=\t%5lu\n", sizeof(symmetric_key));
   printf("\thash_state\t=\t%5lu\n", sizeof(hash_state));
   printf("\thmac_state\t=\t%5lu\n", sizeof(hmac_state));
   printf("\tomac_state\t=\t%5lu\n", sizeof(omac_state));
   printf("\tpmac_state\t=\t%5lu\n", sizeof(pmac_state));
   printf("\tocb_state\t=\t%5lu\n", sizeof(ocb_state));
   printf("\teax_state\t=\t%5lu\n", sizeof(eax_state));
   printf("\tmp_int\t\t=\t%5lu\n", sizeof(mp_int));
#ifdef MRSA
   printf("\trsa_key\t\t=\t%5lu\n", sizeof(rsa_key));
#endif
#ifdef MDSA
   printf("\tdsa_key\t\t=\t%5lu\n", sizeof(dsa_key));
#endif
#ifdef MDH
   printf("\tdh_key\t\t=\t%5lu\n", sizeof(dh_key));
#endif
#ifdef MECC
   printf("\tecc_key\t\t=\t%5lu\n", sizeof(ecc_key));
#endif

   printf("\n\n");
   // do tests
   for (current_test = 0; tests[current_test].name != NULL; current_test++) {
       printf("[%-20s]: ", tests[current_test].name); fflush(stdout);
       printf("\t%s\n", tests[current_test].entry()==0?"passed":"failed"); 
   }
   
   return 0;
}
