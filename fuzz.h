#ifndef DROPBEAR_FUZZ_H
#define DROPBEAR_FUZZ_H

#include "includes.h"
#include "buffer.h"

#ifdef DROPBEAR_FUZZ

void svr_setup_fuzzer(void);

struct dropbear_fuzz_options {
    int fuzzing;

    // to record an unencrypted stream
    FILE* recordf;

    // fuzzing input
    buffer input;

    // dropbear_exit() jumps back
    sigjmp_buf jmp;

    uid_t pw_uid;
    gid_t pw_gid;
    char* pw_name;
    char* pw_dir;
    char* pw_shell;
    char* pw_passwd;
};

extern struct dropbear_fuzz_options fuzz;

#endif

#endif /* DROPBEAR_FUZZ_H */
