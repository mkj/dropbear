/* Makes safe primes of a DR nature */
#include <tommath.h>

const int sizes[] = { 8, 19, 28, 37, 55, 74,  110, 147 };
int main(void)
{
   int res, x, y;
   char buf[4096];
   FILE *out;
   mp_int a, b;
   
   mp_init(&a);
   mp_init(&b);
   
   out = fopen("drprimes.txt", "w");
   for (x = 0; x < (int)(sizeof(sizes)/sizeof(sizes[0])); x++) {
       printf("Seeking a %d-bit safe prime\n", sizes[x] * DIGIT_BIT);
       mp_grow(&a, sizes[x]);
       mp_zero(&a);
       for (y = 1; y < sizes[x]; y++) {
           a.dp[y] = MP_MASK;
       }
       
       /* make a DR modulus */
       a.dp[0] = 1;
       a.used = sizes[x];
       
       /* now loop */
       do { 
          fflush(stdout);
          mp_prime_next_prime(&a, 3);
          printf(".");
          mp_sub_d(&a, 1, &b);
          mp_div_2(&b, &b);
          mp_prime_is_prime(&b, 3, &res);  
	} while (res == 0);          
        
        if (mp_dr_is_modulus(&a) != 1) {
           printf("Error not DR modulus\n");
        } else {
           mp_toradix(&a, buf, 10);
           printf("\n\np == %s\n\n", buf);
           fprintf(out, "%d-bit prime:\np == %s\n\n", mp_count_bits(&a), buf); fflush(out);
        }           
   }
   fclose(out);
   
   mp_clear(&a);
   mp_clear(&b);
   
   return 0;
}

