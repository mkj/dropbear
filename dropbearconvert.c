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

/* This program converts to/from Dropbear and OpenSSH private-key formats */
#include "options.h"
#include "runopts.h"
#include "signkey.h"
#include "buffer.h"
#include "util.h"
#include "keyimport.h"


static int do_convert(int intype, const char* infile, int outtype,
		const char* outfile);

static void printhelp(char * progname);

static void printhelp(char * progname) {

	fprintf(stderr, "Usage: %s <inputtype> <outputtype> <inputfile> <outputfile>\n\n"
					"All parameters must be specified.\n"
					"\n"
					"Input types:\n"
					"-d   Dropbear keyfile as input\n"
					"-o   OpenSSH keyfile as input\n"
					"Output types:\n"
					"-D   Dropbear keyfile as output\n"
					"-O   OpenSSH keyfile as output\n"
					"\n"
					"The inputfile and output file can be '-' to specify"
					"standard input or standard output.", progname);
}

int main(int argc, char ** argv) {

	sign_key *key;
	buffer *buf;
	char * filename = NULL;
	int intype, outtype;
	const char* infile;
	const char* outfile;

	/* get the commandline options */
	if (argc != 5) {
		goto usage;
	}

	/* input type */
	if (strlen(argv[1]) != 2 || argv[1][0] != '-') {
		goto usage;
	}
	if (argv[1][1] == 'd') {
		intype = KEYFILE_DROPBEAR;
	} else if (argv[1][1] == 'o') {
		intype = KEYFILE_OPENSSH;
	} else {
		goto usage;
	}

	/* output type */
	if (strlen(argv[2]) != 2 || argv[2][0] != '-') {
		goto usage;
	}
	if (argv[2][1] == 'd') {
		outtype = KEYFILE_DROPBEAR;
	} else if (argv[2][1] == 'o') {
		outtype = KEYFILE_OPENSSH;
	} else {
		goto usage;
	}

	infile = argv[3];
	outfile = argv[4];

	return do_convert(intype, infile, outtype, outfile);

usage:
	printhelp(argv[0]);
	return 1;
}

static int do_convert(int intype, const char* infile, int outtype,
		const char* outfile) {

	sign_key * key;
	char * keytype;

	key = import_read(infile, NULL, intype);
	if (!key) {
		fprintf(stderr, "Error reading key from '%s'\n",
				infile);
		return 1;
	}

	keytype = key->rsakey != NULL ? "RSA" : "DSS";

	fprintf(stderr, "Key is a %s key\n", keytype);

	if (import_write(outfile, key, NULL, outtype) != 1) {
		fprintf(stderr, "Error writing key to '%s'\n",
				outfile);
		return 1;
	} else {
		fprintf(stderr, "Wrote key to '%s'\n",
				outfile);
		return 0;
	}
}
