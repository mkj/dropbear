/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

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
