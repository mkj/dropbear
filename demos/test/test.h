#ifndef __TEST_H_
#define __TEST_H_

#include "mycrypt.h"

/* enable stack testing */
// #define STACK_TEST

/* stack testing, define this if stack usage goes downwards [e.g. x86] */
#define STACK_DOWN

typedef struct {
    char *name, *prov, *req;
    int  (*entry)(void);
} test_entry;

extern prng_state test_yarrow;


void stack_masker(void);
void stack_check(void);
extern unsigned long stack_cur;
#define stack_chk(x) { stack_check(); if (stack_cur >= 1024) { fprintf(stderr, " Warning: Stack usage of %lu in %s, %s:%d\n", stack_cur, x, __FILE__, __LINE__); } }

void run_cmd(int res, int line, char *file, char *cmd);
#define DO(x) { stack_masker(); run_cmd((x), __LINE__, __FILE__, #x); stack_chk(#x); }

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
int der_tests(void);

#endif
