#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdio.h>
#include <assert.h>

/* Debugging */

/*#define DEBUG_KEXHASH*/
/*#define DEBUG_RSA*/

/* Don't clear environment variables, useful if we are debugging with
 * something requiring LD_PRELOAD etc, but dangerous if used normally */
/*#define DEBUG_KEEP_ENV*/

/* Whether we should try to free() all allocated memory at exit.
 * not required, but useful if running memory checkers like valgrind,
 * to check for leaks */
/*#define DOCLEANUP*/

/* Define this to print trace statements */
/*#define DEBUG_TRACE*/

/* you don't need to touch this block */
#ifdef DEBUG_TRACE
#define TRACE(X) (dropbear_trace X)
#else /*DEBUG_TRACE*/
#define TRACE(X)
#endif /*DEBUG_TRACE*/

/* For testing as non-root on shadowed systems, include the crypt of a password
 * here. You can then log in as any user with this password. Ensure that you
 * make your own password, and are careful about using this. This will also
 * disable some of the chown pty code etc*/
/* #define HACKCRYPT "hL8nrFDt0aJ3E" */ /* this is crypt("password") */

#endif
