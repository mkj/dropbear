/* 
 * Name      : ch1-03.c
 * Purpose   : Demonstration of variable length outputs
 * Author    : Tom St Denis
 *
 * History   : v0.79 Initial release
 */
 
 /* ch1-01-1 */
 #include <mycrypt.h>
 
 int main(void)
 {
    unsigned long length;
    unsigned char buffer[512];
    int errno;
    
    length = sizeof(buffer);
    if ((errno = some_func(..., buffer, &length)) != CRYPT_OK) {
       printf("Error: %s\n", error_to_string(errno));
       return EXIT_FAILURE;
    }
    printf("Size of output is %lu bytes\n", length);
    return 0;
}
/* ch1-01-1 */


    