/* 
 * Name      : ch2-01.c
 * Purpose   : Demonstration of reading the RNG
 * Author    : Tom St Denis
 *
 * History   : v0.81 Initial release
 */
 
 /* ch2-02-2 */
 #include <mycrypt.h>
 
 int main(void) 
 {
    unsigned char buf[16];
    unsigned long len;
    int           ix;
    
    /* read the RNG */
    len = rng_get_bytes(buf, sizeof(buf), NULL);
    
    /* verify return */
    if (len != sizeof(buf)) {
       printf("Error: Only read %lu bytes.\n", len);
    } else {
       printf("Read %lu bytes\n", len);
       for (ix = 0; ix < sizeof(buf); ix++) {
           printf("%02x ", buf[ix]);
       }
       printf("\n");
    }
    
    return EXIT_SUCCESS;
}
/* ch2-02-2 */

