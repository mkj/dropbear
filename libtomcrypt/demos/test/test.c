#include "test.h"

test_entry tests[26];

test_entry test_list[26] = { 

/* test name          provides    requires             entry */
{"store_test",             "a",         "",          store_test           },
{"cipher_hash_test",       "b",        "a",          cipher_hash_test     },
{"modes_test",             "c",        "b",          modes_test           },
{"mac_test",               "d",        "c",          mac_test             },
{"pkcs_1_test",            "e",        "b",          pkcs_1_test          },
{"rsa_test",               "f",        "e",          rsa_test             },
{"ecc_test",               "g",        "a",          ecc_tests            },
{"dsa_test",               "h",        "a",          dsa_test             },
{"dh_test",                "i",        "a",          dh_tests             },

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

   if (register_prng(&yarrow_desc) == -1) {
      printf("Error registering yarrow PRNG\n");
      exit(-1);
   }

   if (register_prng(&sprng_desc) == -1) {
      printf("Error registering sprng PRNG\n");
      exit(-1);
   }
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
   
int main(void)
{
   printf("Built with\n%s\n", crypt_build_settings);

   srand(time(NULL));
   sort();
   register_algs();
      
   // start dummy yarrow for internal use 
   DO(yarrow_start(&test_yarrow));
   DO(yarrow_add_entropy("test", 4, &test_yarrow));
   DO(yarrow_ready(&test_yarrow));

   // do tests
   for (current_test = 0; tests[current_test].name != NULL; current_test++) {
       printf("[%-20s]: ", tests[current_test].name); fflush(stdout);
       printf("\t%s\n", tests[current_test].entry()==0?"passed":"failed"); 
   }
   
   return 0;
}
