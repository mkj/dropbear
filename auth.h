#ifndef _AUTH_H_
#define _AUTH_H_

#include "options.h"
#include "pwd.h"

void authinitialise();

void recv_msg_userauth_request();
void send_msg_userauth_failure(int partial, int incrfail);
void send_msg_userauth_success();

#define MAX_USERNAME_LEN 25 /* arbitrary for the moment */

#define AUTH_TYPE_PUBKEY	1 << 0
#define AUTH_TYPE_PASSWORD	1 << 1

/* auth types, "none" means we should return list of acceptable types */
#define AUTH_METHOD_NONE	"none"
#define AUTH_METHOD_NONE_LEN 4
#define AUTH_METHOD_PUBKEY "publickey"
#define AUTH_METHOD_PUBKEY_LEN 9
#define AUTH_METHOD_PASSWORD "password"
#define AUTH_METHOD_PASSWORD_LEN 8

#define CHECK_USER_RETURN 0
#define CHECK_USER_CONTINUE 1

struct AuthState {

	char *username; /* This is the username the client presents to check. It
					   is updated each run through, used for auth checking */
	struct passwd * pw;
	unsigned char authtypes; /* Flags indicating which auth types are still 
								valid */
	unsigned int failcount; /* Number of (failed) authentication attempts.*/
	unsigned authdone : 1; /* 0 if we haven't authed, 1 if we have */


};

#endif /* _AUTH_H_ */
