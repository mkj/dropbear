/* This header is meant to be included before mycrypt.h in projects where
 * you don't want to throw all the defines in a makefile. 
 */

#ifndef MYCRYPT_CUSTOM_H_
#define MYCRYPT_CUSTOM_H_

#ifdef CRYPT
	#error mycrypt_custom.h should be included before mycrypt.h
#endif

/* macros for various libc functions */
#define XMALLOC malloc
#define XREALLOC realloc
#define XCALLOC calloc
#define XFREE free
#define XCLOCK clock
#define XCLOCKS_PER_SEC CLOCKS_PER_SEC

/* Use small code where possible */
#define SMALL_CODE

/* Enable self-test test vector checking */
#define LTC_TEST

/* clean the stack of functions which put private information on stack */
//#define CLEAN_STACK

/* disable all file related functions */
//#define NO_FILE

/* various ciphers */
#define BLOWFISH
#define RC2
#define RC5
#define RC6
#define SAFERP
#define RIJNDAEL
#define XTEA
#define TWOFISH
#define TWOFISH_TABLES
//#define TWOFISH_ALL_TABLES
//#define TWOFISH_SMALL
#define DES
#define CAST5
#define NOEKEON
#define SKIPJACK

/* modes of operation */
#define CFB
#define OFB
#define ECB
#define CBC
#define CTR

/* hash functions */
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
#define YARROW
// which descriptor of AES to use? 
// 0 = rijndael_enc 1 = aes_enc, 2 = rijndael [full], 3 = aes [full]
#define YARROW_AES 0
#define SPRNG
#define RC4
#define DEVRANDOM
#define TRY_URANDOM_FIRST

/* Public Key Neatoness */
#define MRSA
#define RSA_TIMING                   // enable RSA side channel timing prevention 
#define MDSA
#define MDH
#define MECC
#define DH768
#define DH1024
#define DH1280
#define DH1536
#define DH1792
#define DH2048
#define DH2560
#define DH3072
#define DH4096
#define ECC160
#define ECC192
#define ECC224
#define ECC256
#define ECC384
#define ECC521
#define MPI

/* PKCS #1 and 5 stuff */
#define PKCS_1
#define PKCS_5

#include <mycrypt.h>

#endif

