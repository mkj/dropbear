#ifndef DROPBEAR_FUZZ_H
#define DROPBEAR_FUZZ_H

#include "includes.h"
#include "buffer.h"

#ifdef DROPBEAR_FUZZ

// once per process
void svr_setup_fuzzer(void);

// once per input. returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE
int fuzzer_set_input(const uint8_t *Data, size_t Size);

struct dropbear_fuzz_options {
    int fuzzing;

    // to record an unencrypted stream
    FILE* recordf;

    // fuzzing input
    buffer *input;

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
