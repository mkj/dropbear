#include "includes.h"

/* definitions are cleanest if we just put them here */
int dropbear_main(int argc, char ** argv);
int dropbearkey_main(int argc, char ** argv);
int dropbearconvert_main(int argc, char ** argv);

int main(int argc, char ** argv) {

	char * progname;

	if (argc > 0) {
		/* figure which form we're being called as */
		progname = basename(argv[0]);

#ifdef DBMULTI_DROPBEAR
		if (strcmp(progname, "dropbear") == 0) {
			return dropbear_main(argc, argv);
		}
#endif
#ifdef DBMULTI_KEY
		if (strcmp(progname, "dropbearkey") == 0) {
			return dropbearkey_main(argc, argv);
		}
#endif
#ifdef DBMULTI_CONVERT
		if (strcmp(progname, "dropbearconvert") == 0) {
			return dropbearconvert_main(argc, argv);
		}
#endif
	}

	fprintf(stderr, "Dropbear multi-purpose version %s\n"
			"Make a symlink pointing at this binary with one of the following names:\n"
#ifdef DBMULTI_DROPBEAR
			"'dropbear' - the Dropbear server\n"
#endif
#ifdef DBMULTI_KEY
			"'dropbearkey' - the key generator\n"
#endif
#ifdef DBMULTI_CONVERT
			"'dropbearconvert' - the key converter\n"
#endif
			,
			DROPBEAR_VERSION);
	exit(1);

}
