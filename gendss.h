#ifndef _GENDSS_H_
#define _GENDSS_H_

#include "dss.h"

#ifdef DROPBEAR_DSS

dss_key * gen_dss_priv_key(unsigned int size);

#endif /* DROPBEAR_DSS */

#endif /* _GENDSS_H_ */
