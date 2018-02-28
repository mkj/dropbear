#include "fuzz.h"
#include "session.h"
#include "fuzz-wrapfd.h"
#include "debug.h"

static void setup_fuzzer(void) {
	fuzz_common_setup();
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	static int once = 0;
	if (!once) {
		setup_fuzzer();
		once = 1;
	}

	if (fuzz_set_input(Data, Size) == DROPBEAR_FAILURE) {
		return 0;
	}

	m_malloc_set_epoch(1);

	/* choose a keytype based on input */
	uint8_t b = 0;
	size_t i;
	for (i = 0; i < Size; i++) {
		b ^= Data[i];
	}
	const char* algoname = fuzz_signkey_names[b%DROPBEAR_SIGNKEY_NUM_NAMED];
	const char* keyblob = "blob"; /* keep short */

	if (setjmp(fuzz.jmp) == 0) {
		fuzz_checkpubkey_line(fuzz.input, 5, "/home/me/authorized_keys", 
			algoname, strlen(algoname),
			(unsigned char*)keyblob, strlen(keyblob));
		m_malloc_free_epoch(1, 0);
	} else {
		m_malloc_free_epoch(1, 1);
		TRACE(("dropbear_exit longjmped"))
		/* dropbear_exit jumped here */
	}

	return 0;
}
