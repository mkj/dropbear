#ifndef _GENRSA_H_
#define _GENRSA_H_

#include "rsa.h"

#ifdef DROPBEAR_RSA

rsa_key * gen_rsa_priv_key(unsigned int size);

#endif /* DROPBEAR_RSA */

#endif /* _GENRSA_H_ */
