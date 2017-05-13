#include "includes.h"

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

int main(int argc, char ** argv) {
    LLVMFuzzerTestOneInput("hello", 5);
    return 0;
}
