#include "includes.h"

#include "includes.h"
#include "fuzz.h"
#include "dbutil.h"
#include "runopts.h"
#include "crypto_desc.h"
#include "session.h"
#include "dbrandom.h"
#include "fuzz-wrapfd.h"

struct dropbear_fuzz_options fuzz;

static void fuzz_dropbear_log(int UNUSED(priority), const char* format, va_list param);
static void load_fixed_hostkeys(void);

void common_setup_fuzzer(void) {
    fuzz.fuzzing = 1;
    fuzz.wrapfds = 1;
    fuzz.input = m_malloc(sizeof(buffer));
    _dropbear_log = fuzz_dropbear_log;
    crypto_init();
}

int fuzzer_set_input(const uint8_t *Data, size_t Size) {

    fuzz.input->data = (unsigned char*)Data;
    fuzz.input->size = Size;
    fuzz.input->len = Size;
    fuzz.input->pos = 0;

    memset(&ses, 0x0, sizeof(ses));
    memset(&svr_ses, 0x0, sizeof(svr_ses));

    // get prefix. input format is
    // string prefix
    //     uint32 wrapfd seed
    //     ... to be extended later
    // [bytes] ssh input stream

    // be careful to avoid triggering buffer.c assertions
    if (fuzz.input->len < 8) {
        return DROPBEAR_FAILURE;
    }
    size_t prefix_size = buf_getint(fuzz.input);
    if (prefix_size != 4) {
        return DROPBEAR_FAILURE;
    }
    uint32_t wrapseed = buf_getint(fuzz.input);
    wrapfd_setup(wrapseed);

    fuzz_seed();

    return DROPBEAR_SUCCESS;
}

static void fuzz_dropbear_log(int UNUSED(priority), const char* format, va_list param) {

    char printbuf[1024];

#if DEBUG_TRACE
    if (debug_trace) {
        vsnprintf(printbuf, sizeof(printbuf), format, param);
        fprintf(stderr, "%s\n", printbuf);
    }
#endif
}

void svr_setup_fuzzer(void) {
    struct passwd *pw;

    common_setup_fuzzer();
    
    _dropbear_exit = svr_dropbear_exit;

    char *argv[] = { 
        "-E", 
    };

    int argc = sizeof(argv) / sizeof(*argv);
    svr_getopts(argc, argv);

    /* user lookups might be slow, cache it */
    pw = getpwuid(getuid());
    dropbear_assert(pw);
    fuzz.pw_name = m_strdup(pw->pw_name);
    fuzz.pw_dir = m_strdup(pw->pw_dir);
    fuzz.pw_shell = m_strdup(pw->pw_shell);
    fuzz.pw_passwd = m_strdup("!!zzznope");

    load_fixed_hostkeys();
}

static void load_fixed_hostkeys(void) {
#include "fuzz-hostkeys.c"   

    buffer *b = buf_new(3000);
    enum signkey_type type;

    TRACE(("load fixed hostkeys"))

    svr_opts.hostkey = new_sign_key();

    buf_setlen(b, 0);
    buf_putbytes(b, keyr, keyr_len);
    buf_setpos(b, 0);
    type = DROPBEAR_SIGNKEY_RSA;
    if (buf_get_priv_key(b, svr_opts.hostkey, &type) == DROPBEAR_FAILURE) {
        dropbear_exit("failed fixed rsa hostkey");
    }

    buf_setlen(b, 0);
    buf_putbytes(b, keyd, keyd_len);
    buf_setpos(b, 0);
    type = DROPBEAR_SIGNKEY_DSS;
    if (buf_get_priv_key(b, svr_opts.hostkey, &type) == DROPBEAR_FAILURE) {
        dropbear_exit("failed fixed dss hostkey");
    }

    buf_setlen(b, 0);
    buf_putbytes(b, keye, keye_len);
    buf_setpos(b, 0);
    type = DROPBEAR_SIGNKEY_ECDSA_NISTP256;
    if (buf_get_priv_key(b, svr_opts.hostkey, &type) == DROPBEAR_FAILURE) {
        dropbear_exit("failed fixed ecdsa hostkey");
    }

    buf_free(b);
}

void fuzz_kex_fakealgos(void) {
    ses.newkeys->recv.crypt_mode = &dropbear_mode_none;
}
