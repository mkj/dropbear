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
#define BLOWFISH
#define RIJNDAEL
#define TWOFISH
#define DES
#define CBC
#define CTR
#define SHA512
#define SHA1
#define MD5
#define HMAC
#define BASE64
#define MPI
#define YARROW


#include <mycrypt.h>

#endif

