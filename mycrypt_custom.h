/* This header is meant to be included before mycrypt.h in projects where
 * you don't want to throw all the defines in a makefile. 
 */

#ifndef MYCRYPT_CUSTOM_H_
#define MYCRYPT_CUSTOM_H_

/* macros for various libc functions you can change for embedded targets */
#define XMALLOC  malloc
#define XREALLOC realloc
#define XCALLOC  calloc
#define XFREE    free

#define XMEMSET  memset
#define XMEMCPY  memcpy

#define XCLOCK   clock
#define XCLOCKS_PER_SEC CLOCKS_PER_SEC

/* Use small code where possible */
// #define SMALL_CODE

/* Enable self-test test vector checking */
#define LTC_TEST

/* clean the stack of functions which put private information on stack */
// #define CLEAN_STACK

/* disable all file related functions */
// #define NO_FILE

/* various ciphers */
#define BLOWFISH
#define RC2
#define RC5
#define RC6
#define SAFERP
#define RIJNDAEL
#define XTEA
/* _TABLES tells it to use tables during setup, _SMALL means to use the smaller scheduled key format
 * (saves 4KB of ram), _ALL_TABLES enables all tables during setup */
#define TWOFISH
#define TWOFISH_TABLES
// #define TWOFISH_ALL_TABLES
// #define TWOFISH_SMALL
/* DES includes EDE triple-DES */
#define DES
#define CAST5
#define NOEKEON
#define SKIPJACK
/* SAFER code isn't public domain.  It appears to be free to use 
 * but has been disabled by default to avoid any such problems 
 */
//#define SAFER

/* block cipher modes of operation */
#define CFB
#define OFB
#define ECB
#define CBC
#define CTR

/* hash functions */
#define CHC_HASH
#define WHIRLPOOL
#define SHA512
#define SHA384
#define SHA256
#define SHA224
#define TIGER
#define SHA1
#define MD5
#define MD4
#define MD2
#define RIPEMD128
#define RIPEMD160

/* MAC functions */
#define HMAC
#define OMAC
#define PMAC

/* Encrypt + Authenticate Modes */
#define EAX_MODE
#define OCB_MODE

/* Various tidbits of modern neatoness */
#define BASE64

/* Yarrow */
#define YARROW
// which descriptor of AES to use? 
// 0 = rijndael_enc 1 = aes_enc, 2 = rijndael [full], 3 = aes [full]
#define YARROW_AES 0

#if defined(YARROW) && !defined(CTR)
   #error YARROW requires CTR chaining mode to be defined!
#endif

#define SPRNG
#define RC4

/* Fortuna PRNG */
#define FORTUNA
/* reseed every N calls to the read function */
#define FORTUNA_WD    10
/* number of pools (4..32) can save a bit of ram by lowering the count */
#define FORTUNA_POOLS 32

/* Greg's SOBER128 PRNG ;-0 */
#define SOBER128

#define DEVRANDOM
#define TRY_URANDOM_FIRST

/* Public Key Neatoness */
#define MRSA
/* enable RSA side channel timing prevention */
#define RSA_TIMING

/* Digital Signature Algorithm */
#define MDSA
/* Max diff between group and modulus size in bytes */
#define MDSA_DELTA     512
/* Max DSA group size in bytes (default allows 4k-bit groups) */
#define MDSA_MAX_GROUP 512

/* Diffie-Hellman */
#define MDH
/* Supported Key Sizes */
#define DH768
#define DH1024
#define DH1280
#define DH1536
#define DH1792
#define DH2048
#define DH2560
#define DH3072
#define DH4096

/* ECC */
#define MECC
/* Supported Key Sizes */
#define ECC160
#define ECC192
#define ECC224
#define ECC256
#define ECC384
#define ECC521

/* Include the MPI functionality?  (required by the PK algorithms) */
#define MPI

/* PKCS #1 (RSA) and #5 (Password Handling) stuff */
#define PKCS_1
#define PKCS_5

#endif

