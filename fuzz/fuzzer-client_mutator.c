#include "fuzz.h"

#include "fuzz-sshpacketmutator.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	return fuzz_run_client(Data, Size, 0);
}

