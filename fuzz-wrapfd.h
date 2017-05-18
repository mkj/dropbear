#ifndef FUZZ_WRAPFD_H
#define FUZZ_WRAPFD_H

#include "buffer.h"

enum wrapfd_mode {
    UNUSED = 0,
    PLAIN,
    INPROGRESS,
    RANDOMIN,
};

void wrapfd_setup(uint32_t wrapseed);
// doesn't take ownership of buf. buf is optional.
void wrapfd_add(int fd, buffer *buf, enum wrapfd_mode mode);

#endif // FUZZ_WRAPFD_H
