#include <mycrypt.h>

#define KTIMES  25
#define TIMES   100000

struct list {
    int id;
    unsigned long spd1, spd2, avg;
} results[100];

int no_results;

int sorter(const void *a, const void *b)
{
   const struct list *A, *B;
   A = a;
   B = b;
   if (A->avg < B->avg) return -1;
   if (A->avg > B->avg) return 1;
   return 0;
}

void tally_results(int type)
{
   int x;

   // qsort the results
   qsort(results, no_results, sizeof(struct list), &sorter);

   printf("\n");
   if (type == 0) {
      for (x = 0; x < no_results; x++) {
         printf("%-20s: Schedule at %6lu\n", cipher_descriptor[results[x].id].name, (unsigned long)results[x].spd1);
      } 
   } else if (type == 1) {
      for (x = 0; x < no_results; x++) {
        printf
          ("%-20s: Encrypt at %5lu, Decrypt at %5lu\n", cipher_descriptor[results[x].id].name, results[x].spd1, results[x].spd2);
      }
   } else {
      for (x = 0; x < no_results; x++) {
        printf
          ("%-20s: Process at %5lu\n", hash_descriptor[results[x].id].name, results[x].spd1 / 1000);
      }
   }
}

/* RDTSC from Scott Duplichan */
static ulong64 rdtsc (void)
   {
   #if defined __GNUC__
      #if defined(__i386__) || defined(__x86_64__)
         unsigned long long a;
         __asm__ __volatile__ ("rdtsc\nmovl %%eax,%0\nmovl %%edx,4+%0\n"::"m"(a):"%eax","%edx");
         return a;
      #else /* gcc-IA64 version */
         unsigned long result;
         __asm__ __volatile__("mov %0=ar.itc" : "=r"(result) :: "memory");
         while (__builtin_expect ((int) result == -1, 0))
         __asm__ __volatile__("mov %0=ar.itc" : "=r"(result) :: "memory");
         return result;
      #endif

   // Microsoft and Intel Windows compilers
   #elif defined _M_IX86
     __asm rdtsc
   #elif defined _M_AMD64
     return __rdtsc ();
   #elif defined _M_IA64
     #if defined __INTEL_COMPILER
       #include <ia64intrin.h>
     #endif
      return __getReg (3116);
   #else
     #error need rdtsc function for this build
   #endif
   }

ulong64 timer, skew = 0;
prng_state prng;

void t_start(void)
{
   timer = rdtsc();
}

ulong64 t_read(void)
{
   return rdtsc() - timer;
}

void init_timer(void)
{
   ulong64 c1, c2, t1, t2, t3;
   unsigned long y1;

   c1 = c2 = (ulong64)-1;
   for (y1 = 0; y1 < TIMES*100; y1++) {
      t_start();
      t1 = t_read();
      t3 = t_read();
      t2 = t_read() - t1;

      c1 = (c1 > t1) ? t1 : c1;
      c2 = (c2 > t2) ? t2 : c2;
   }
   skew = c2 - c1;
   printf("Clock Skew: %lu\n", (unsigned long)skew);
}

void reg_algs(void)
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
#ifdef CHC_HASH
  register_hash(&chc_desc);
  if ((err = chc_register(register_cipher(&aes_desc))) != CRYPT_OK) {
     printf("chc_register error: %s\n", error_to_string(err));
     exit(EXIT_FAILURE);
  }
#endif


#ifndef YARROW 
   #error This demo requires Yarrow.
#endif
register_prng(&yarrow_desc);
#ifdef FORTUNA
register_prng(&fortuna_desc);
#endif
#ifdef RC4
register_prng(&rc4_desc);
#endif
#ifdef SOBER128
register_prng(&sober128_desc);
#endif

rng_make_prng(128, find_prng("yarrow"), &prng, NULL);
}

int time_keysched(void)
{
  unsigned long x, y1;
  ulong64 t1, c1;
  symmetric_key skey;
  int kl;
  int    (*func) (const unsigned char *, int , int , symmetric_key *);
  unsigned char key[MAXBLOCKSIZE];

  printf ("\n\nKey Schedule Time Trials for the Symmetric Ciphers:\n(Times are cycles per key)\n");
  no_results = 0; 
 for (x = 0; cipher_descriptor[x].name != NULL; x++) {
#define DO1(k)   func(k, kl, 0, &skey);

    func = cipher_descriptor[x].setup;
    kl   = cipher_descriptor[x].min_key_length;
    c1 = (ulong64)-1;
    for (y1 = 0; y1 < KTIMES; y1++) {
       yarrow_read(key, kl, &prng);
       t_start();
       DO1(key);
       t1 = t_read();
       c1 = (t1 > c1) ? c1 : t1;
    }
    t1 = c1 - skew;
    results[no_results].spd1 = results[no_results].avg = t1;
    results[no_results++].id = x;
    printf("."); fflush(stdout);

#undef DO1
   }
   tally_results(0);

   return 0;
}

int time_cipher(void)
{
  unsigned long x, y1;
  ulong64  t1, t2, c1, c2, a1, a2;
  symmetric_key skey;
  void    (*func) (const unsigned char *, unsigned char *, symmetric_key *);
  unsigned char key[MAXBLOCKSIZE], pt[MAXBLOCKSIZE];
  int err;

  printf ("\n\nECB Time Trials for the Symmetric Ciphers:\n");
  no_results = 0;
  for (x = 0; cipher_descriptor[x].name != NULL; x++) {
    cipher_descriptor[x].setup (key, cipher_descriptor[x].min_key_length, 0,
                &skey);

    /* sanity check on cipher */
    if ((err = cipher_descriptor[x].test()) != CRYPT_OK) {
       fprintf(stderr, "\n\nERROR: Cipher %s failed self-test %s\n", cipher_descriptor[x].name, error_to_string(err));
       exit(EXIT_FAILURE);
    }

#define DO1   func(pt,pt,&skey);
#define DO2   DO1 DO1

    func = cipher_descriptor[x].ecb_encrypt;
    c1 = c2 = (ulong64)-1;
    for (y1 = 0; y1 < TIMES; y1++) {
        t_start();
        DO1;
        t1 = t_read();
        DO2;
        t2 = t_read();
        t2 -= t1;

        c1 = (t1 > c1 ? c1 : t1);
        c2 = (t2 > c2 ? c2 : t2);
    }
    a1 = c2 - c1 - skew;


    func = cipher_descriptor[x].ecb_decrypt;
    c1 = c2 = (ulong64)-1;
    for (y1 = 0; y1 < TIMES; y1++) {
        t_start();
        DO1;
        t1 = t_read();
        DO2;
        t2 = t_read();
        t2 -= t1;

        c1 = (t1 > c1 ? c1 : t1);
        c2 = (t2 > c2 ? c2 : t2);
    }
    a2 = c2 - c1 - skew;
    
    results[no_results].id = x;
    results[no_results].spd1 = a1/cipher_descriptor[x].block_length;
    results[no_results].spd2 = a2/cipher_descriptor[x].block_length;;
    results[no_results].avg = (results[no_results].spd1 + results[no_results].spd2+1)/2;
    ++no_results;
    printf("."); fflush(stdout);
    
#undef DO2
#undef DO1
   }
   tally_results(1);

   return 0;
}

int time_hash(void)
{
  unsigned long x, y1, len;
  ulong64 t1, t2, c1, c2;
  hash_state md;
  int    (*func)(hash_state *, const unsigned char *, unsigned long), err;
  unsigned char pt[MAXBLOCKSIZE];


  printf ("\n\nHASH Time Trials for:\n");
  no_results = 0;
  for (x = 0; hash_descriptor[x].name != NULL; x++) {

    /* sanity check on hash */
    if ((err = hash_descriptor[x].test()) != CRYPT_OK) {
       fprintf(stderr, "\n\nERROR: Hash %s failed self-test %s\n", hash_descriptor[x].name, error_to_string(err));
       exit(EXIT_FAILURE);
    }

    hash_descriptor[x].init(&md);

#define DO1   func(&md,pt,len);
#define DO2   DO1 DO1

    func = hash_descriptor[x].process;
    len  = hash_descriptor[x].blocksize;

    c1 = c2 = (ulong64)-1;
    for (y1 = 0; y1 < TIMES; y1++) {
       t_start();
       DO1;
       t1 = t_read();
       DO2;
       t2 = t_read() - t1;
       c1 = (t1 > c1) ? c1 : t1;
       c2 = (t2 > c2) ? c2 : t2;
    }
    t1 = c2 - c1 - skew;
    t1 = ((t1 * CONST64(1000))) / ((ulong64)hash_descriptor[x].blocksize);
    results[no_results].id = x;
    results[no_results].spd1 = results[no_results].avg = t1;
    ++no_results;
    printf("."); fflush(stdout);
#undef DO2
#undef DO1
   }
   tally_results(2);

   return 0;
}

void time_mult(void)
{
   ulong64 t1, t2;
   unsigned long x, y;
   mp_int  a, b, c;

   printf("Timing Multiplying:\n");
   mp_init_multi(&a,&b,&c,NULL);
   for (x = 128/DIGIT_BIT; x <= 1024/DIGIT_BIT; x += 128/DIGIT_BIT) {
       mp_rand(&a, x);
       mp_rand(&b, x);

#define DO1 mp_mul(&a, &b, &c);
#define DO2 DO1; DO1;

       t2 = -1;
       for (y = 0; y < TIMES; y++) {
           t_start();
           t1 = t_read();
           DO2;
           t1 = (t_read() - t1)>>1;
           if (t1 < t2) t2 = t1;
       }
       printf("%3lu digits: %9llu cycles\n", x, t2);
   }
   mp_clear_multi(&a,&b,&c,NULL);

#undef DO1
#undef DO2
}      

void time_sqr(void)
{
   ulong64 t1, t2;
   unsigned long x, y;
   mp_int  a, b;

   printf("Timing Squaring:\n");
   mp_init_multi(&a,&b,NULL);
   for (x = 128/DIGIT_BIT; x <= 1024/DIGIT_BIT; x += 128/DIGIT_BIT) {
       mp_rand(&a, x);

#define DO1 mp_sqr(&a, &b);
#define DO2 DO1; DO1;

       t2 = -1;
       for (y = 0; y < TIMES; y++) {
           t_start();
           t1 = t_read();
           DO2;
           t1 = (t_read() - t1)>>1;
           if (t1 < t2) t2 = t1;
       }
       printf("%3lu digits: %9llu cycles\n", x, t2);
   }
   mp_clear_multi(&a,&b,NULL);

#undef DO1
#undef DO2
}    
   
void time_prng(void)
{
   ulong64 t1, t2;
   unsigned char buf[4096];
   prng_state tprng;
   unsigned long x, y;
   int           err;

   printf("Timing PRNGs (cycles/byte output, cycles add_entropy (32 bytes) :\n");
   for (x = 0; prng_descriptor[x].name != NULL; x++) {

      /* sanity check on prng */
      if ((err = prng_descriptor[x].test()) != CRYPT_OK) {
         fprintf(stderr, "\n\nERROR: PRNG %s failed self-test %s\n", prng_descriptor[x].name, error_to_string(err));
         exit(EXIT_FAILURE);
      }

      prng_descriptor[x].start(&tprng);
      zeromem(buf, 256);
      prng_descriptor[x].add_entropy(buf, 256, &tprng);
      prng_descriptor[x].ready(&tprng);
      t2 = -1;

#define DO1 if (prng_descriptor[x].read(buf, 4096, &tprng) != 4096) { printf("\n\nERROR READ != 4096\n\n"); exit(EXIT_FAILURE); }
#define DO2 DO1 DO1
      for (y = 0; y < 10000; y++) {
         t_start();
         t1 = t_read();
         DO2;
         t1 = (t_read() - t1)>>1;
         if (t1 < t2) t2 = t1;
      }
      printf("%20s: %5llu ", prng_descriptor[x].name, t2>>12);
#undef DO2
#undef DO1

#define DO1 prng_descriptor[x].start(&tprng); prng_descriptor[x].add_entropy(buf, 32, &tprng); prng_descriptor[x].ready(&tprng); prng_descriptor[x].done(&tprng);
#define DO2 DO1 DO1
      for (y = 0; y < 10000; y++) {
         t_start();
         t1 = t_read();
         DO2;
         t1 = (t_read() - t1)>>1;
         if (t1 < t2) t2 = t1;
      }
      printf("%5llu\n", t2);
#undef DO2
#undef DO1

   }
}
      
/* time various RSA operations */
void time_rsa(void)
{
   rsa_key key;
   ulong64 t1, t2;
   unsigned char buf[2][4096];
   unsigned long x, y, z, zzz;
   int           err, zz;

   for (x = 1024; x <= 2048; x += 512) {
       t2 = 0;
       for (y = 0; y < 16; y++) {
           t_start();
           t1 = t_read();
           if ((err = rsa_make_key(&prng, find_prng("yarrow"), x/8, 65537, &key)) != CRYPT_OK) {
              fprintf(stderr, "\n\nrsa_make_key says %s, wait...no it should say %s...damn you!\n", error_to_string(err), error_to_string(CRYPT_OK));
              exit(EXIT_FAILURE);
           }
           t1 = t_read() - t1;
           t2 += t1;

           if (y < 15) {
              rsa_free(&key);
           }
       }
       t2 >>= 4;
       printf("RSA-%lu make_key    took %15llu cycles\n", x, t2);

       t2 = 0;
       for (y = 0; y < 16; y++) {
           t_start();
           t1 = t_read();
           z = sizeof(buf[1]);
           if ((err = rsa_encrypt_key(buf[0], 32, buf[1], &z, "testprog", 8, &prng,
                                      find_prng("yarrow"), find_hash("sha1"),
                                      &key)) != CRYPT_OK) {
              fprintf(stderr, "\n\nrsa_encrypt_key says %s, wait...no it should say %s...damn you!\n", error_to_string(err), error_to_string(CRYPT_OK));
              exit(EXIT_FAILURE);
           }
           t1 = t_read() - t1;
           t2 += t1;
       }
       t2 >>= 4;
       printf("RSA-%lu encrypt_key took %15llu cycles\n", x, t2);

       t2 = 0;
       for (y = 0; y < 16; y++) {
           t_start();
           t1 = t_read();
           zzz = sizeof(buf[0]);
           if ((err = rsa_decrypt_key(buf[1], z, buf[0], &zzz, "testprog", 8, &prng,
                                      find_prng("yarrow"), find_hash("sha1"), 
                                      &zz, &key)) != CRYPT_OK) {
              fprintf(stderr, "\n\nrsa_decrypt_key says %s, wait...no it should say %s...damn you!\n", error_to_string(err), error_to_string(CRYPT_OK));
              exit(EXIT_FAILURE);
           }
           t1 = t_read() - t1;
           t2 += t1;
       }
       t2 >>= 4;
       printf("RSA-%lu decrypt_key took %15llu cycles\n", x, t2);


       rsa_free(&key);
  }
}

/* time various ECC operations */
void time_ecc(void)
{
   ecc_key key;
   ulong64 t1, t2;
   unsigned char buf[2][4096];
   unsigned long i, x, y, z;
   int           err;
   static unsigned long sizes[] = {160/8, 256/8, 521/8, 100000};

   for (x = sizes[i=0]; x < 100000; x = sizes[++i]) {
       t2 = 0;
       for (y = 0; y < 16; y++) {
           t_start();
           t1 = t_read();
           if ((err = ecc_make_key(&prng, find_prng("yarrow"), x, &key)) != CRYPT_OK) {
              fprintf(stderr, "\n\necc_make_key says %s, wait...no it should say %s...damn you!\n", error_to_string(err), error_to_string(CRYPT_OK));
              exit(EXIT_FAILURE);
           }
           t1 = t_read() - t1;
           t2 += t1;

           if (y < 15) {
              ecc_free(&key);
           }
       }
       t2 >>= 4;
       printf("ECC-%lu make_key    took %15llu cycles\n", x*8, t2);

       t2 = 0;
       for (y = 0; y < 16; y++) {
           t_start();
           t1 = t_read();
           z = sizeof(buf[1]);
           if ((err = ecc_encrypt_key(buf[0], 20, buf[1], &z, &prng, find_prng("yarrow"), find_hash("sha1"),
                                      &key)) != CRYPT_OK) {
              fprintf(stderr, "\n\necc_encrypt_key says %s, wait...no it should say %s...damn you!\n", error_to_string(err), error_to_string(CRYPT_OK));
              exit(EXIT_FAILURE);
           }
           t1 = t_read() - t1;
           t2 += t1;
       }
       t2 >>= 4;
       printf("ECC-%lu encrypt_key took %15llu cycles\n", x*8, t2);
       ecc_free(&key);
  }
}

/* time various DH operations */
void time_dh(void)
{
   dh_key key;
   ulong64 t1, t2;
   unsigned char buf[2][4096];
   unsigned long i, x, y, z;
   int           err;
   static unsigned long sizes[] = {768/8, 1024/8, 1536/8, 2048/8, 3072/8, 4096/8, 100000};

   for (x = sizes[i=0]; x < 100000; x = sizes[++i]) {
       t2 = 0;
       for (y = 0; y < 16; y++) {
           t_start();
           t1 = t_read();
           if ((err = dh_make_key(&prng, find_prng("yarrow"), x, &key)) != CRYPT_OK) {
              fprintf(stderr, "\n\ndh_make_key says %s, wait...no it should say %s...damn you!\n", error_to_string(err), error_to_string(CRYPT_OK));
              exit(EXIT_FAILURE);
           }
           t1 = t_read() - t1;
           t2 += t1;

           if (y < 15) {
              dh_free(&key);
           }
       }
       t2 >>= 4;
       printf("DH-%4lu make_key    took %15llu cycles\n", x*8, t2);

       t2 = 0;
       for (y = 0; y < 16; y++) {
           t_start();
           t1 = t_read();
           z = sizeof(buf[1]);
           if ((err = dh_encrypt_key(buf[0], 20, buf[1], &z, &prng, find_prng("yarrow"), find_hash("sha1"),
                                      &key)) != CRYPT_OK) {
              fprintf(stderr, "\n\ndh_encrypt_key says %s, wait...no it should say %s...damn you!\n", error_to_string(err), error_to_string(CRYPT_OK));
              exit(EXIT_FAILURE);
           }
           t1 = t_read() - t1;
           t2 += t1;
       }
       t2 >>= 4;
       printf("DH-%4lu encrypt_key took %15llu cycles\n", x*8, t2);
       dh_free(&key);
  }
}

#define MAC_SIZE 32
void time_macs(void)
{
   unsigned char *buf, key[16], tag[16];
   ulong64 t1, t2;
   unsigned long x, z;
   int err, cipher_idx, hash_idx;

   printf("\nMAC Timings (cycles/byte on %dKB blocks):\n", MAC_SIZE);

   buf = XMALLOC(MAC_SIZE*1024);
   if (buf == NULL) {
      fprintf(stderr, "\n\nout of heap yo\n\n");
      exit(EXIT_FAILURE);
   }

   cipher_idx = find_cipher("aes");
   hash_idx   = find_hash("md5");

   yarrow_read(buf, MAC_SIZE*1024, &prng);
   yarrow_read(key, 16, &prng);

   t2 = -1;
   for (x = 0; x < 10000; x++) {
        t_start();
        t1 = t_read();
        z = 16;
        if ((err = omac_memory(cipher_idx, key, 16, buf, MAC_SIZE*1024, tag, &z)) != CRYPT_OK) {
           fprintf(stderr, "\n\nomac error... %s\n", error_to_string(err));
           exit(EXIT_FAILURE);
        }
        t1 = t_read() - t1;
        if (t1 < t2) t2 = t1;
   }
   printf("OMAC-AES\t\t%9llu\n", t2/(MAC_SIZE*1024));

   t2 = -1;
   for (x = 0; x < 10000; x++) {
        t_start();
        t1 = t_read();
        z = 16;
        if ((err = pmac_memory(cipher_idx, key, 16, buf, MAC_SIZE*1024, tag, &z)) != CRYPT_OK) {
           fprintf(stderr, "\n\npmac error... %s\n", error_to_string(err));
           exit(EXIT_FAILURE);
        }
        t1 = t_read() - t1;
        if (t1 < t2) t2 = t1;
   }
   printf("PMAC-AES\t\t%9llu\n", t2/(MAC_SIZE*1024));

   t2 = -1;
   for (x = 0; x < 10000; x++) {
        t_start();
        t1 = t_read();
        z = 16;
        if ((err = hmac_memory(hash_idx, key, 16, buf, MAC_SIZE*1024, tag, &z)) != CRYPT_OK) {
           fprintf(stderr, "\n\nhmac error... %s\n", error_to_string(err));
           exit(EXIT_FAILURE);
        }
        t1 = t_read() - t1;
        if (t1 < t2) t2 = t1;
   }
   printf("HMAC-MD5\t\t%9llu\n", t2/(MAC_SIZE*1024));

   XFREE(buf);
}

int main(void)
{
  reg_algs();

  printf("Timings for ciphers and hashes.  Times are listed as cycles per byte processed.\n\n");

//  init_timer();
  time_mult();
  time_sqr();
  time_rsa();
  time_dh();
  time_ecc();
  time_prng();
  time_cipher();
  time_keysched();
  time_hash();
  time_macs();

  return EXIT_SUCCESS;
}

