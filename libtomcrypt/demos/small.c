// small demo app that just includes a cipher/hash/prng

#include <mycrypt.h>

int main(void)
{
   register_cipher(&rijndael_desc);
   register_prng(&yarrow_desc);
   register_hash(&sha256_desc);
   return 0;
}
