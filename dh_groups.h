#ifndef DROPBEAR_DH_GROUPS_H
#define DROPBEAR_DH_GROUPS_H
#include "options.h"

#define DH_P_1_LEN 128
extern const unsigned char dh_p_1[DH_P_1_LEN];
#define DH_P_14_LEN 256
extern const unsigned char dh_p_14[DH_P_14_LEN];

#ifdef DROPBEAR_DH_GROUP15
#define DH_P_15_LEN 384
extern const unsigned char dh_p_15[DH_P_15_LEN];
#endif

#ifdef DROPBEAR_DH_GROUP16
#define DH_P_16_LEN 512
extern const unsigned char dh_p_16[DH_P_16_LEN];
#endif


extern const int DH_G_VAL;


#endif
