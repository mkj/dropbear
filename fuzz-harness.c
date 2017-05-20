#include "includes.h"
#include "buffer.h"
#include "dbutil.h"

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

int main(int argc, char ** argv) {
    int i;
    buffer *input = buf_new(100000);

#if DROPBEAR_TRACE
    debug_trace = 1;
#endif

    for (i = 1; i < argc; i++) {
        char* fn = argv[i];
        buf_setlen(input, 0);
        buf_readfile(input, fn);
        buf_setpos(input, 0);

        printf("Running %s\n", fn);
        LLVMFuzzerTestOneInput(input->data, input->len);
        printf("Done %s\n", fn);
    }

    printf("Finished\n");

    return 0;
}
