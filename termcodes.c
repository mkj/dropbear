#include <unistd.h>
#include <termios.h>

#include "options.h"
#include "termcodes.h"

const struct TermCode termcodes[] = {

		{0}, /* TTY_OP_END */
		{VINTR, TERMCODE_CONTROLCHAR}, /* control character codes */
		{VQUIT, TERMCODE_CONTROLCHAR},
		{VERASE, TERMCODE_CONTROLCHAR},
		{VKILL, TERMCODE_CONTROLCHAR},
		{VEOF, TERMCODE_CONTROLCHAR},
		{VEOL, TERMCODE_CONTROLCHAR},
		{VEOL2, TERMCODE_CONTROLCHAR},
		{VSTART, TERMCODE_CONTROLCHAR},
		{VSTOP, TERMCODE_CONTROLCHAR},
		{VSUSP, TERMCODE_CONTROLCHAR},
#ifdef VDSUSP
		{VDSUSP, TERMCODE_CONTROLCHAR},
#else
		{0},
#endif
		{VREPRINT, TERMCODE_CONTROLCHAR},
		{VWERASE, TERMCODE_CONTROLCHAR},
		{VLNEXT, TERMCODE_CONTROLCHAR},
#ifdef VFLUSH
		{VFLUSH, TERMCODE_CONTROLCHAR},
#else	
		{0},
#endif
#ifdef VSWTCH
		{VSWTCH, TERMCODE_CONTROLCHAR},
#else	
		{0},
#endif
#ifdef VSTATUS
		{VSTATUS, TERMCODE_CONTROLCHAR},
#else
		{0},
#endif
		{VDISCARD, TERMCODE_CONTROLCHAR},
		{0}, /* 19 */
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0}, /* 29 */
		{IGNPAR, TERMCODE_INPUT}, /* input flags */
		{PARMRK, TERMCODE_INPUT},
		{INPCK, TERMCODE_INPUT},
		{ISTRIP, TERMCODE_INPUT},
		{INLCR, TERMCODE_INPUT},
		{IGNCR, TERMCODE_INPUT},
		{ICRNL, TERMCODE_INPUT},
#ifdef IUCLC
		{IUCLC, TERMCODE_INPUT},
#else
		{0},
#endif
		{IXON, TERMCODE_INPUT},
		{IXANY, TERMCODE_INPUT},
		{IXOFF, TERMCODE_INPUT},
#ifdef IMAXBELL
		{IMAXBELL, TERMCODE_INPUT},
#else
		{0},
#endif
		{0}, /* 42 */
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0}, /* 49 */
		{ISIG, TERMCODE_LOCAL}, /* local flags */
		{ICANON, TERMCODE_LOCAL},
#ifdef XCASE
		{XCASE, TERMCODE_LOCAL},
#else
		{0},
#endif
		{ECHO, TERMCODE_LOCAL},
		{ECHOE, TERMCODE_LOCAL},
		{ECHOK, TERMCODE_LOCAL},
		{ECHONL, TERMCODE_LOCAL},
		{NOFLSH, TERMCODE_LOCAL},
		{TOSTOP, TERMCODE_LOCAL},
		{IEXTEN, TERMCODE_LOCAL},
		{ECHOCTL, TERMCODE_LOCAL},
		{ECHOKE, TERMCODE_LOCAL},
		{PENDIN, TERMCODE_LOCAL},
		{0}, /* 63 */
		{0},
		{0},
		{0},
		{0},
		{0},
		{0}, /* 69 */
		{OPOST, TERMCODE_OUTPUT}, /* output flags */
#ifdef OLCUC
		{OLCUC, TERMCODE_OUTPUT},
#else
		{0},
#endif
		{ONLCR, TERMCODE_OUTPUT},
#ifdef OCRNL
		{OCRNL, TERMCODE_OUTPUT},
#else
		{0},
#endif
#ifdef ONOCR
		{ONOCR, TERMCODE_OUTPUT},
#else
		{0},
#endif
#ifdef ONLRET
		{ONLRET, TERMCODE_OUTPUT},
#else
		{0},
#endif
		{0}, /* 76 */
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0},
		{0}, /* 89 */
		{CS7, TERMCODE_CONTROL},
		{CS8, TERMCODE_CONTROL},
		{PARENB, TERMCODE_CONTROL},
		{PARODD, TERMCODE_CONTROL},
		/* 94 */
};
