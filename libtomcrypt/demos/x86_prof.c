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
      #ifdef i386
         ulong64 a;
         asm volatile("rdtsc ":"=A" (a));
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

register_prng(&yarrow_desc);
rng_make_prng(128, find_prng("yarrow"), &prng, NULL);
}

int time_keysched(void)
{
  unsigned long x, i, y1;
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


  printf ("\n\nECB Time Trials for the Symmetric Ciphers:\n");
  no_results = 0;
  for (x = 0; cipher_descriptor[x].name != NULL; x++) {
    cipher_descriptor[x].setup (key, cipher_descriptor[x].min_key_length, 0,
                &skey);

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
  int    (*func)(hash_state *, const unsigned char *, unsigned long);
  unsigned char pt[MAXBLOCKSIZE];


  printf ("\n\nHASH Time Trials for:\n");
  no_results = 0;
  for (x = 0; hash_descriptor[x].name != NULL; x++) {
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

int main(void)
{
  reg_algs();

  printf("Timings for ciphers and hashes.  Times are listed as cycles per byte processed.\n\n");

//  init_timer();
  time_cipher();
  time_keysched();
  time_hash();

  return EXIT_SUCCESS;
}

