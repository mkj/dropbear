#include <tomcrypt_test.h>

void run_cmd(int res, int line, char *file, char *cmd)
{
   if (res != CRYPT_OK) {
      fprintf(stderr, "%s (%d)\n%s:%d:%s\n", error_to_string(res), res, file, line, cmd);
      exit(EXIT_FAILURE);
   }
}

/* $Source: /cvs/libtom/libtomcrypt/testprof/test.c,v $ */
/* $Revision: 1.6 $ */
/* $Date: 2005/05/05 14:35:59 $ */
