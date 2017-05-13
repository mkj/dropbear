#include "fuzz.h"
#include "dbrandom.h"
#include "session.h"

static int setup_fuzzer(void) {
	svr_setup_fuzzer();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	static int once = 0;
	if (!once) {
		setup_fuzzer();
		once = 1;
	}

	fuzz.input.data = (unsigned char*)Data;
	fuzz.input.size = Size;
	fuzz.input.len = Size;
	fuzz.input.pos = 0;

	seedrandom();

	if (setjmp(fuzz.jmp) == 0) {
		svr_session(-1, -1);
	} else {
		// dropbear_exit jumped here
	}

	return 0;
}
