/* This header is meant to be included before mycrypt.h in projects where
 * you don't want to throw all the defines in a makefile. 
 */

#ifndef MYCRYPT_CUSTOM_H_
#define MYCRYPT_CUSTOM_H_

#ifdef CRYPT
    #error mycrypt_custom.h should be included before mycrypt.h
#endif

#define XMALLOC malloc
#define XREALLOC realloc
#define XCALLOC calloc
#define XFREE free
#define XCLOCK clock
#define XCLOCKS_PER_SEC CLOCKS_PER_SEC
#define SMALL_CODE
#define LTC_TEST
#define BLOWFISH
#define RC2
#define RC5
#define RC6
#define SAFERP
#define SAFER
#define RIJNDAEL
#define XTEA
#define TWOFISH
#define DES
#define CAST5
#define NOEKEON
#define CFB
#define OFB
#define ECB
#define CBC
#define CTR
#define SHA512
#define SHA384
#define SHA256
#define TIGER
#define SHA1
#define MD5
#define MD4
#define MD2
#define HMAC
#define BASE64
#define YARROW
#define SPRNG
#define RC4
#define DEVRANDOM
#define MRSA
#define MDH
#define MECC
#define KR
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


#include <mycrypt.h>

#endif

