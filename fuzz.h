#ifndef DROPBEAR_FUZZ_H
#define DROPBEAR_FUZZ_H

#include "config.h"
#ifdef DROPBEAR_FUZZ

#include "includes.h"
#include "buffer.h"
#include "algo.h"
#include "fuzz-wrapfd.h"

// once per process
void svr_setup_fuzzer(void);

// once per input. returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE
int fuzzer_set_input(const uint8_t *Data, size_t Size);

void fuzz_kex_fakealgos(void);

// fake IO wrappers
#ifndef FUZZ_SKIP_WRAP
#define select(nfds, readfds, writefds, exceptfds, timeout) \
        wrapfd_select(nfds, readfds, writefds, exceptfds, timeout)
#define write(fd, buf, count) wrapfd_write(fd, buf, count)
#define read(fd, buf, count) wrapfd_read(fd, buf, count)
#define close(fd) wrapfd_close(fd)
#endif // FUZZ_SKIP_WRAP

struct dropbear_fuzz_options {
    int fuzzing;

    // to record an unencrypted stream
    FILE* recordf;

    // fuzzing input
    buffer *input;
    struct dropbear_cipher recv_cipher;
    struct dropbear_hash recv_mac;
    int wrapfds;

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

#endif // DROPBEAR_FUZZ

#endif /* DROPBEAR_FUZZ_H */
