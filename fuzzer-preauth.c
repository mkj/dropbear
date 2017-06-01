#include "fuzz.h"
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

	// get prefix. input format is
	// string prefix
	//     uint32 wrapfd seed
	//     ... to be extended later
	// [bytes] ssh input stream

	// be careful to avoid triggering buffer.c assertions
	if (fuzz.input->len < 8) {
		return 0;
	}
	size_t prefix_size = buf_getint(fuzz.input);
	if (prefix_size != 4) {
		return 0;
	}
	uint32_t wrapseed = buf_getint(fuzz.input);
	wrapfd_setseed(wrapseed);

	int fakesock = 20;
	wrapfd_add(fakesock, fuzz.input, PLAIN);

	m_malloc_set_epoch(1);
	if (setjmp(fuzz.jmp) == 0) {
		svr_session(fakesock, fakesock);
		m_malloc_free_epoch(1, 0);
	} else {
		m_malloc_free_epoch(1, 1);
		TRACE(("dropbear_exit longjmped"))
		// dropbear_exit jumped here
	}

	return 0;
}
