#ifndef _RUNOPTS_H_
#define _RUNOPTS_H_

#include "options.h"
#include "signkey.h"
#include "buffer.h"

struct RunOpts {

	char * rsakeyfile;
	char * dsskeyfile;
	char * bannerfile;
	int forkbg;
	
	sign_key *hostkey;
	buffer * banner;

};

typedef struct RunOpts runopts;

runopts * getrunopts(int argc, char ** argv);

#endif /* _RUNOPTS_H_ */
