#include "fuzz.h"
#include "dbrandom.h"
#include "session.h"
#include "fuzz-wrapfd.h"
#include "debug.h"

static void setup_fuzzer(void) {
	svr_setup_fuzzer();
	//debug_trace = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	static int once = 0;
	if (!once) {
		setup_fuzzer();
		once = 1;
	}

	if (fuzzer_set_input(Data, Size) == DROPBEAR_FAILURE) {
		return 0;
	}

	int fakesock = 1;
	wrapfd_add(fakesock, fuzz.input, PLAIN);

	if (setjmp(fuzz.jmp) == 0) {
		svr_session(fakesock, fakesock);
	} else {
		TRACE(("dropbear_exit longjmped"))
		// dropbear_exit jumped here
	}

	return 0;
}
