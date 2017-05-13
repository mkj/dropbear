#include "includes.h"

#ifdef DROPBEAR_FUZZ

#include "includes.h"
#include "fuzz.h"
#include "dbutil.h"
#include "runopts.h"

struct dropbear_fuzz_options fuzz;

static void load_fixed_hostkeys(void);

static void common_setup_fuzzer(void) {
    fuzz.fuzzing = 1;
}

void svr_setup_fuzzer(void) {
    struct passwd *pw;

    common_setup_fuzzer();

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

#endif /* DROPBEAR_FUZZ */
