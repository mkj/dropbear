/* test pmac/omac/hmac */
#include "test.h"

int mac_test(void)
{
   DO(hmac_test()); 
   DO(pmac_test()); 
   DO(omac_test()); 
   DO(eax_test());  
   DO(ocb_test());  
   return 0;
}
