#include <tomcrypt_test.h>

int main(void)
{
init_timer();
reg_algs();
time_keysched();
time_cipher();
time_cipher2();
time_cipher3();
time_hash();
time_macs();
time_encmacs();
time_prng();
time_mult();
time_sqr();
time_rsa();
time_ecc();
time_dh();
return EXIT_SUCCESS;

}

/* $Source: /cvs/libtom/libtomcrypt/demos/timing.c,v $ */
/* $Revision: 1.17 $ */
/* $Date: 2005/06/23 02:16:26 $ */
