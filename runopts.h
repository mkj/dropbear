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

#ifndef _RUNOPTS_H_
#define _RUNOPTS_H_

#include "includes.h"
#include "signkey.h"
#include "buffer.h"

struct RunOpts {

	char * rsakeyfile;
	char * dsskeyfile;
	char * bannerfile;
	int forkbg;

	/* ports is an array of the portcount listening ports */
	uint16_t *ports;
	unsigned int portcount;

	/* Flags indicating whether to use ipv4 and ipv6 */
	/* not used yet
	int ipv4;
	int ipv6;
	*/

#ifdef DO_MOTD
	/* whether to print the MOTD */
	int domotd;
#endif

	int norootlogin;
	
	sign_key *hostkey;
	buffer * banner;

};

typedef struct RunOpts runopts;

runopts * getrunopts(int argc, char ** argv);
void freerunopts(runopts* opts);

#endif /* _RUNOPTS_H_ */
