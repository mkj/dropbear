#ifndef _KEYIMPORT_H_
#define _KEYIMPORT_H_

#include "includes.h"
#include "signkey.h"

enum {
	KEYFILE_DROPBEAR,
	KEYFILE_OPENSSH,
	KEYFILE_SSHCOM
};

int import_write(const char *filename, sign_key *key, char *passphrase,
		int filetype);
sign_key *import_read(const char *filename, char *passphrase, int filetype);
int import_encrypted(const char* filename, int filetype);

#endif /* _KEYIMPORT_H_ */
