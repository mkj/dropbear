#include <mycrypt.h>

extern void t_start(void);
extern ulong64  t_read(void);

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

#define TIMES  20

int time_cipher(void)
{
  unsigned long x, y1;
  ulong64 t1, t2;
  symmetric_key skey;
  void    (*func) (const unsigned char *, unsigned char *, symmetric_key *);
  unsigned char key[MAXBLOCKSIZE], pt[MAXBLOCKSIZE];


  printf ("\n\nECB Time Trials for the Symmetric Ciphers:\n");
  for (x = 0; cipher_descriptor[x].name != NULL; x++) {
    cipher_descriptor[x].setup (key, cipher_descriptor[x].min_key_length, 0,
                &skey);

#define DO1   func(pt,pt,&skey);
#define DO2   DO1 DO1
#define DO4   DO2 DO2
#define DO8   DO4 DO4
#define DO16  DO8 DO8
#define DO32  DO16 DO16
#define DO64  DO32 DO32
#define DO128 DO64 DO64
#define DO256 DO128 DO128

    func = cipher_descriptor[x].ecb_encrypt;
    y1 = 1<<TIMES;
    t_start();
    do {
      DO256;
    } while ((y1 -= 256) > 0);
    t1 = t_read();

    func = cipher_descriptor[x].ecb_decrypt;
    y1 = 1<<TIMES;
    t_start();
    do {
      DO256;
    } while ((y1 -= 256) > 0);
    t2 = t_read();
    
    t1 = ((t1 * CONST64(1000)) >> TIMES) / ((ulong64)cipher_descriptor[x].block_length);
    t2 = ((t2 * CONST64(1000)) >> TIMES) / ((ulong64)cipher_descriptor[x].block_length);
    
    printf
      ("%-20s: Encrypt at %5.3f, Decrypt at %5.3f\n", cipher_descriptor[x].name, t1/1000.0, t2/1000.0);

#undef DO256
#undef DO128
#undef DO64
#undef DO32
#undef DO16
#undef DO8
#undef DO4
#undef DO2
#undef DO1
   }
   
   return 0;
}

int time_hash(void)
{
  unsigned long x, y1, len;
  ulong64 t1;
  hash_state md;
  void    (*func)(hash_state *, const unsigned char *, unsigned long);
  unsigned char pt[MAXBLOCKSIZE];

 
  printf ("HASH Time Trials for:\n");
  for (x = 0; hash_descriptor[x].name != NULL; x++) {
    hash_descriptor[x].init(&md);

#define DO1   func(&md,pt,len);
#define DO2   DO1 DO1
#define DO4   DO2 DO2
#define DO8   DO4 DO4
#define DO16  DO8 DO8
#define DO32  DO16 DO16
#define DO64  DO32 DO32
#define DO128 DO64 DO64
#define DO256 DO128 DO128

    func = hash_descriptor[x].process;
    len  = hash_descriptor[x].blocksize;
    y1 = 1<<TIMES;
    t_start();
    do {
      DO256;
    } while ((y1 -= 256) > 0);
    t1 = t_read();
   
    t1 = ((t1 * CONST64(1000)) >> TIMES) / ((ulong64)hash_descriptor[x].blocksize);
    
    printf
      ("%-20s: Process at %5.3f\n", hash_descriptor[x].name, t1 / 1000.0);

#undef DO256
#undef DO128
#undef DO64
#undef DO32
#undef DO16
#undef DO8
#undef DO4
#undef DO2
#undef DO1
   }
   
   return 0;
}

int main(void)
{
  reg_algs();

  printf("Timings for ciphers and hashes.  Times are listed as cycles per byte processed.\n\n");
  
  time_hash();
  time_cipher();
  
  return EXIT_SUCCESS;
}  

