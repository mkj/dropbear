/* test pmac/omac/hmac */
#include <tomcrypt_test.h>

int mac_test(void)
{
#ifdef HMAC
   DO(hmac_test()); 
#endif
#ifdef PMAC
   DO(pmac_test()); 
#endif
#ifdef OMAC
   DO(omac_test()); 
#endif
#ifdef EAX_MODE
   DO(eax_test());  
#endif
#ifdef OCB_MODE
   DO(ocb_test());  
#endif
#ifdef CCM_MODE
   DO(ccm_test());
#endif
#ifdef GCM_MODE
   DO(gcm_test());
#endif
#ifdef PELICAN
   DO(pelican_test());
#endif
   return 0;
}
