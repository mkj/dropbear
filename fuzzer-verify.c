#include "fuzz.h"
#include "session.h"
#include "fuzz-wrapfd.h"
#include "debug.h"

static void setup_fuzzer(void) {
	common_setup_fuzzer();
}

static buffer *verifydata;

/* Tests reading a public key and verifying a signature */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	static int once = 0;
	if (!once) {
		setup_fuzzer();
		verifydata = buf_new(30);
		buf_putstring(verifydata, "x", 1);
		once = 1;
	}

	if (fuzzer_set_input(Data, Size) == DROPBEAR_FAILURE) {
		return 0;
	}

	m_malloc_set_epoch(1);

	if (setjmp(fuzz.jmp) == 0) {
		sign_key *key = new_sign_key();
		enum signkey_type type = DROPBEAR_SIGNKEY_ANY;
		if (buf_get_pub_key(fuzz.input, key, &type) == DROPBEAR_SUCCESS) {
			/* Don't expect random fuzz input to verify */
			assert(buf_verify(fuzz.input, key, verifydata) == DROPBEAR_FAILURE);
		}
		sign_key_free(key);
		m_malloc_free_epoch(1, 0);
	} else {
		m_malloc_free_epoch(1, 1);
		TRACE(("dropbear_exit longjmped"))
		// dropbear_exit jumped here
	}

	return 0;
}
