#ifndef _KEX_H_
#define _KEX_H_

#include "options.h"
#include "session.h"

void send_msg_kexinit();
void recv_msg_kexinit();
void send_dh_kex();
void recv_msg_kexdh_init();
void send_msg_newkeys();
void recv_msg_newkeys();
void kexinitialise();

struct KEXState {

	unsigned sentkexinit : 1; /*set when we've sent/recv kexinit packet */
	unsigned recvkexinit : 1;
	unsigned firstfollows : 1; /* true when first_kex_packet_follows is set */
	unsigned sentnewkeys : 1; /* set once we've send/recv'ed MSG_NEWKEYS*/
	unsigned recvnewkeys : 1;

	long lastkextime; /* time of the last kex */
	unsigned int datatrans; /* data transmitted since last kex */
	unsigned int datarecv; /* data received since last kex */

};

#define MAX_KEXHASHBUF 2000

#endif /* _KEX_H_ */
