#ifndef _PACKET_H_

#define _PACKET_H_

#include "options.h"
#include "session.h"

void write_packet();
void read_packet();
void decrypt_packet();
void process_packet();
void encrypt_packet();

#define PACKET_PADDING_OFF 4
#define PACKET_PAYLOAD_OFF 5

#define INIT_READBUF 200

#define CHECKCLEARTOWRITE() assert(ses.writepayload->len == 0 \
								&& ses.writepayload->pos == 0)

#endif /* _PACKET_H_ */
