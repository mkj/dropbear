/* Defines the _ARGCHK macro used within the library */

/* ch1-01-1 */
/* ARGTYPE is defined in mycrypt_cfg.h */
#if ARGTYPE == 0

#include <signal.h>

/* this is the default LibTomCrypt macro  */
extern void crypt_argchk(char *v, char *s, int d);
#define _ARGCHK(x) if (!(x)) { crypt_argchk(#x, __FILE__, __LINE__); }

#elif ARGTYPE == 1

/* fatal type of error */
#define _ARGCHK(x) assert((x))

#elif ARGTYPE == 2

#define _ARGCHK(x) 

#endif
/* ch1-01-1 */

