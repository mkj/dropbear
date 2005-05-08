/* Defines the LTC_ARGCHK macro used within the library */
/* ARGTYPE is defined in mycrypt_cfg.h */
#if ARGTYPE == 0

#include <signal.h>

/* this is the default LibTomCrypt macro  */
void crypt_argchk(char *v, char *s, int d);
#define LTC_ARGCHK(x) if (!(x)) { crypt_argchk(#x, __FILE__, __LINE__); }

#elif ARGTYPE == 1

/* fatal type of error */
#define LTC_ARGCHK(x) assert((x))

#elif ARGTYPE == 2

#define LTC_ARGCHK(x) 

#endif

