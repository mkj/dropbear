/* 
 * Name      : ch1-02.c
 * Purpose   : Demonstration of error handling
 * Author    : Tom St Denis
 *
 * History   : v0.79 Initial release
 */
 
/* ch1-01-1 */
#include <mycrypt.h>

int main(void)
{
   int errno;
   
   if ((errno = some_func(...)) != CRYPT_OK) {
      printf("Error: %s\n", error_to_string(errno));
      return EXIT_FAILURE;
   }
   
   return 0;
}
/*ch1-01-1 */


