#include "mycrypt.h"
#include <signal.h>

#define TAB_SIZE    32

struct _cipher_descriptor cipher_descriptor[TAB_SIZE] = {
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL } };

struct _hash_descriptor hash_descriptor[TAB_SIZE] = {
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL },
{ NULL, 0, 0, 0, NULL, NULL, NULL, NULL } };

struct _prng_descriptor prng_descriptor[TAB_SIZE] = {
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL },
{ NULL, NULL, NULL, NULL, NULL } };

/* ch1-01-1 */
#if (ARGTYPE == 0)
void crypt_argchk(char *v, char *s, int d)
{
#ifdef SONY_PS2
 printf("_ARGCHK '%s' failure on line %d of file %s\n",
         v, d, s);
#else
 fprintf(stderr, "_ARGCHK '%s' failure on line %d of file %s\n",
         v, d, s);
#endif
 (void)raise(SIGABRT);
}
#endif
/* ch1-01-1 */

int find_cipher(const char *name)
{
   int x;
   _ARGCHK(name != NULL);
   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x].name != NULL && !strcmp(cipher_descriptor[x].name, name)) {
          return x;
       }
   }
   return -1;
}

int find_hash(const char *name)
{
   int x;
   _ARGCHK(name != NULL);
   for (x = 0; x < TAB_SIZE; x++) {
       if (hash_descriptor[x].name != NULL && strcmp(hash_descriptor[x].name, name) == 0) {
          return x;
       }
   }
   return -1;
}

int find_prng(const char *name)
{
   int x;
   _ARGCHK(name != NULL);
   for (x = 0; x < TAB_SIZE; x++) {
       if ((prng_descriptor[x].name != NULL) && strcmp(prng_descriptor[x].name, name) == 0) {
          return x;
       }
   }
   return -1;
}

int find_cipher_id(unsigned char ID)
{
   int x;
   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x].ID == ID) {
          return (cipher_descriptor[x].name == NULL) ? -1 : x;
       }
   }
   return -1;
}

int find_hash_id(unsigned char ID)
{
   int x;
   for (x = 0; x < TAB_SIZE; x++) {
       if (hash_descriptor[x].ID == ID) {
          return (hash_descriptor[x].name == NULL) ? -1 : x;
       }
   }
   return -1;
}

/* idea from Wayne Scott */
int find_cipher_any(const char *name, int blocklen, int keylen)
{
   int x;

   _ARGCHK(name != NULL);

   x = find_cipher(name);
   if (x != -1) return x;

   for (x = 0; cipher_descriptor[x].name != NULL && x < TAB_SIZE; x++) {
       if (blocklen <= (int)cipher_descriptor[x].block_length && keylen <= (int)cipher_descriptor[x].max_key_length) {
          return x;
       }
   }
   return -1;
}

int register_cipher(const struct _cipher_descriptor *cipher)
{
   int x;

   _ARGCHK(cipher != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x].name != NULL && cipher_descriptor[x].ID == cipher->ID) {
          return x;
       }
   }

   /* find a blank spot */
   for (x = 0; x < TAB_SIZE; x++) {
       if (cipher_descriptor[x].name == NULL) {
          memcpy(&cipher_descriptor[x], cipher, sizeof(struct _cipher_descriptor));
          return x;
       }
   }

   /* no spot */
   return -1;
}

int unregister_cipher(const struct _cipher_descriptor *cipher)
{
   int x;

   _ARGCHK(cipher != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (memcmp(&cipher_descriptor[x], cipher, sizeof(struct _cipher_descriptor)) == 0) {
          cipher_descriptor[x].name = NULL;
          cipher_descriptor[x].ID   = 255;
          return CRYPT_OK;
       }
   }
   return CRYPT_ERROR;
}

int register_hash(const struct _hash_descriptor *hash)
{
   int x;

   _ARGCHK(hash != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (memcmp(&hash_descriptor[x], hash, sizeof(struct _hash_descriptor)) == 0) {
          return x;
       }
   }

   /* find a blank spot */
   for (x = 0; x < TAB_SIZE; x++) {
       if (hash_descriptor[x].name == NULL) {
          memcpy(&hash_descriptor[x], hash, sizeof(struct _hash_descriptor));
          return x;
       }
   }

   /* no spot */
   return -1;
}

int unregister_hash(const struct _hash_descriptor *hash)
{
   int x;

   _ARGCHK(hash != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (memcmp(&hash_descriptor[x], hash, sizeof(struct _hash_descriptor)) == 0) {
          hash_descriptor[x].name = NULL;
          return CRYPT_OK;
       }
   }
   return CRYPT_ERROR;
}

int register_prng(const struct _prng_descriptor *prng)
{
   int x;

   _ARGCHK(prng != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (memcmp(&prng_descriptor[x], prng, sizeof(struct _prng_descriptor)) == 0) {
          return x;
       }
   }

   /* find a blank spot */
   for (x = 0; x < TAB_SIZE; x++) {
       if (prng_descriptor[x].name == NULL) {
          memcpy(&prng_descriptor[x], prng, sizeof(struct _prng_descriptor));
          return x;
       }
   }

   /* no spot */
   return -1;
}

int unregister_prng(const struct _prng_descriptor *prng)
{
   int x;

   _ARGCHK(prng != NULL);

   /* is it already registered? */
   for (x = 0; x < TAB_SIZE; x++) {
       if (memcmp(&prng_descriptor[x], prng, sizeof(struct _prng_descriptor)) != 0) {
          prng_descriptor[x].name = NULL;
          return CRYPT_OK;
       }
   }
   return CRYPT_ERROR;
}

int cipher_is_valid(int idx)
{
   if (idx < 0 || idx >= TAB_SIZE || cipher_descriptor[idx].name == NULL) {
      return CRYPT_INVALID_CIPHER;
   }
   return CRYPT_OK;
}

int hash_is_valid(int idx)
{
   if (idx < 0 || idx >= TAB_SIZE || hash_descriptor[idx].name == NULL) {
      return CRYPT_INVALID_HASH;
   }
   return CRYPT_OK;
}

int prng_is_valid(int idx)
{
   if (idx < 0 || idx >= TAB_SIZE || prng_descriptor[idx].name == NULL) {
      return CRYPT_INVALID_PRNG;
   }
   return CRYPT_OK;
}

const char *crypt_build_settings =
   "LibTomCrypt " SCRYPT "\n\n"
   "Endianess: "
#if defined(ENDIAN_NEUTRAL)
   "neutral\n"
#elif defined(ENDIAN_LITTLE)
   "little"
   #if defined(ENDIAN_32BITWORD)
   " (32-bit words)\n"
   #else
   " (64-bit words)\n"
   #endif
#elif defined(ENDIAN_BIG)
   "big"
   #if defined(ENDIAN_32BITWORD)
   " (32-bit words)\n"
   #else
   " (64-bit words)\n"
   #endif
#endif
   "Clean stack: "
#if defined(CLEAN_STACK)
   "enabled\n"
#else
   "disabled\n"
#endif
   "Ciphers built-in:\n"
#if defined(BLOWFISH)
   "   Blowfish\n"
#endif
#if defined(RC2)
   "   RC2\n"
#endif
#if defined(RC5)
   "   RC5\n"
#endif
#if defined(RC6)
   "   RC6\n"
#endif
#if defined(SAFERP)
   "   Safer+\n"
#endif
#if defined(SAFER)
   "   Safer\n"
#endif
#if defined(RIJNDAEL)
   "   Rijndael\n"
#endif
#if defined(XTEA)
   "   XTEA\n"
#endif
#if defined(TWOFISH)
   "   Twofish "
   #if defined(TWOFISH_SMALL) && defined(TWOFISH_TABLES)
       "(small, tables)\n"
   #elif defined(TWOFISH_SMALL)
       "(small)\n"
   #elif defined(TWOFISH_TABLES)
       "(tables)\n"
   #else
       "\n"
   #endif
#endif
#if defined(DES)
   "   DES\n"
#endif
#if defined(CAST5)
   "   CAST5\n"
#endif
#if defined(NOEKEON)
   "   Noekeon\n"
#endif
#if defined(SKIPJACK)
   "   Skipjack\n"
#endif

    "\nHashes built-in:\n"
#if defined(SHA512)
   "   SHA-512\n"
#endif
#if defined(SHA384)
   "   SHA-384\n"
#endif
#if defined(SHA256)
   "   SHA-256\n"
#endif
#if defined(SHA224)
   "   SHA-224\n"
#endif
#if defined(TIGER)
   "   TIGER\n"
#endif
#if defined(SHA1)
   "   SHA1\n"
#endif
#if defined(MD5)
   "   MD5\n"
#endif
#if defined(MD4)
   "   MD4\n"
#endif
#if defined(MD2)
   "   MD2\n"
#endif
#if defined(RIPEMD128)
   "   RIPEMD128\n"
#endif
#if defined(RIPEMD160)
   "   RIPEMD160\n"
#endif

    "\nBlock Chaining Modes:\n"
#if defined(CFB)
    "   CFB\n"
#endif
#if defined(OFB)
    "   OFB\n"
#endif
#if defined(ECB)
    "   ECB\n"
#endif
#if defined(CBC)
    "   CBC\n"
#endif
#if defined(CTR)
    "   CTR\n"
#endif

    "\nPRNG:\n"
#if defined(YARROW)
    "   Yarrow\n"
#endif
#if defined(SPRNG)
    "   SPRNG\n"
#endif
#if defined(RC4)
    "   RC4\n"
#endif

    "\nPK Algs:\n"
#if defined(MRSA)
    "   RSA\n"
#endif
#if defined(MDH)
    "   DH\n"
#endif
#if defined(MECC)
    "   ECC\n"
#endif
#if defined(KR)
    "   KR\n"
#endif

    "\nCompiler:\n"
#if defined(WIN32)
    "   WIN32 platform detected.\n"
#endif
#if defined(__CYGWIN__)
    "   CYGWIN Detected.\n"
#endif
#if defined(__DJGPP__)
    "   DJGPP Detected.\n"
#endif
#if defined(_MSC_VER)
    "   MSVC compiler detected.\n"
#endif
#if defined(__GNUC__)
    "   GCC compiler detected.\n"
#endif

    "\nVarious others: "
#if defined(GF)
    " GF "
#endif
#if defined(BASE64)
    " BASE64 "
#endif
#if defined(MPI)
    " MPI "
#endif
#if defined(HMAC)
    " HMAC "
#endif
#if defined(TRY_UNRANDOM_FIRST)
    " TRY_UNRANDOM_FIRST "
#endif
#if defined(LTC_TEST)
    " LTC_TEST "
#endif
    "\n"

    "\n\n\n"
    ;

