#ifndef __TEST_H_
#define __TEST_H_

#include "mycrypt.h"

typedef struct {
    char *name, *prov, *req;
    int  (*entry)(void);
} test_entry;

extern prng_state test_yarrow;

void run_cmd(int res, int line, char *file, char *cmd);
#define DO(x) run_cmd((x), __LINE__, __FILE__, #x)



/* TESTS */
int cipher_hash_test(void);
int modes_test(void);
int mac_test(void);
int pkcs_1_test(void);
int store_test(void);
int rsa_test(void);
int ecc_tests(void);
int dsa_test(void);
int dh_tests(void);

#endif
