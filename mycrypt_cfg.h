/* This is the build config file.
 *
 * With this you can setup what to inlcude/exclude automatically during any build.  Just comment
 * out the line that #define's the word for the thing you want to remove.  phew!
 */

#ifndef MYCRYPT_CFG_H
#define MYCRYPT_CFG_H

/* you can change how memory allocation works ... */
void *XMALLOC(size_t n);
void *REALLOC(void *p, size_t n);
void *XCALLOC(size_t n, size_t s);
void XFREE(void *p);

/* change the clock function too */
 clock_t XCLOCK(void);

/* various other functions */
void *XMEMCPY(void *dest, const void *src, size_t n);
int   XMEMCMP(const void *s1, const void *s2, size_t n);

/* type of argument checking, 0=default, 1=fatal and 2=none */
#define ARGTYPE  0

/* Controls endianess and size of registers.  Leave uncommented to get platform neutral [slower] code 
 * 
 * Note: in order to use the optimized macros your platform must support unaligned 32 and 64 bit read/writes.
 * The x86 platforms allow this but some others [ARM for instance] do not.  On those platforms you **MUST**
 * use the portable [slower] macros.
 */

/* detect x86-32 machines somewhat */
#if defined(INTEL_CC) || (defined(_MSC_VER) && defined(WIN32)) || (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__i386__)))
   #define ENDIAN_LITTLE
   #define ENDIAN_32BITWORD
#endif

/* detects MIPS R5900 processors (PS2) */
#if (defined(__R5900) || defined(R5900) || defined(__R5900__)) && (defined(_mips) || defined(__mips__) || defined(mips))
   #define ENDIAN_LITTLE
   #define ENDIAN_64BITWORD
#endif

/* detect amd64 */
#if defined(__x86_64__)
   #define ENDIAN_LITTLE
   #define ENDIAN_64BITWORD
#endif

/* #define ENDIAN_LITTLE */
/* #define ENDIAN_BIG */

/* #define ENDIAN_32BITWORD */
/* #define ENDIAN_64BITWORD */

#if (defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE)) && !(defined(ENDIAN_32BITWORD) || defined(ENDIAN_64BITWORD))
    #error You must specify a word size as well as endianess in mycrypt_cfg.h
#endif

#if !(defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE))
   #define ENDIAN_NEUTRAL
#endif

/* packet code */
#if defined(MRSA) || defined(MDH) || defined(MECC)
    #define PACKET

    /* size of a packet header in bytes */
    #define PACKET_SIZE            4

    /* Section tags */
    #define PACKET_SECT_RSA        0
    #define PACKET_SECT_DH         1
    #define PACKET_SECT_ECC        2
    #define PACKET_SECT_DSA        3

    /* Subsection Tags for the first three sections */
    #define PACKET_SUB_KEY         0
    #define PACKET_SUB_ENCRYPTED   1
    #define PACKET_SUB_SIGNED      2
    #define PACKET_SUB_ENC_KEY     3
#endif

#endif /* MYCRYPT_CFG_H */

