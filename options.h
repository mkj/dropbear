#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include "includes.h"
#include "config.h"
#include "debug.h"
#include "libtomcrypt/mycrypt_custom.h"

/******************************************************************
 * Define compile-time options below.
 ******************************************************************/

#define DROPBEAR_PORT 2244 /* for testing */

/* Hostkey paths */
#define DSS_PRIV_FILENAME "dropbear_dss_host_key"
#define RSA_PRIV_FILENAME "dropbear_rsa_host_key"

/* Encryption - at least one required.
 * SSH2 RFC Draft requires 3DES and recommends blowfish, aes128 & twofish128 */
#define DROPBEAR_AES128_CBC
#define DROPBEAR_BLOWFISH_CBC
#define DROPBEAR_TWOFISH128_CBC
#define DROPBEAR_3DES_CBC

/* Integrity - at least one required.
 * SSH2 RFC Draft requires sha1-hmac, recommends md5-hmac */
#define DROPBEAR_SHA1_HMAC
#define DROPBEAR_MD5_HMAC

/* Hostkey/public key algorithms - at least one required, these are used
 * for hostkey as well as for verifying signatures with pubkey auth.
 * SSH2 RFC Draft requires dss, recommends rsa */
#define DROPBEAR_RSA
#define DROPBEAR_DSS

/* Define DSS_PROTOK to use Putty's method of generating the value k for dss,
 * rather than just from the random byte source.
 * Undefining this will save you ~4k in binary size with static uclibc, but
 * your DSS hostkey could be exposed if the random number source isn't good.
 * If in doubt, leave it defined */
#define DSS_PROTOK

/* Authentication type to use, at least one required.
   SSH2 RFC Draft requires pubkey auth, recommends password */
#define DROPBEAR_PASSWORD_AUTH
#define DROPBEAR_PUBKEY_AUTH

/* Random device to use - you must specify one only.
 * DEV_RANDOM is recommended on hosts with a good /dev/random,
 * otherwise use EGD and run EGD or PRNGD, specifying
 * the socket. This is only used for the initial seed, further
 * entropy is gathered from timings etc */
#define DROPBEAR_DEV_RANDOM /* use /dev/random and /dev/urandom */

/*#undef DROPBEAR_EGD */ /* use egd or prngd socket */
#define DROPBEAR_EGD_SOCKET "./rng"

/* Specify the number of clients we will allow to be connected but
 * not yet authenticated. After this limit, connections are rejected */
#define MAX_UNAUTH_CLIENTS 30

/* The draft RFC recommends 20 tries, 5 seems more sensible */
#define MAX_AUTH_TRIES 5

/*******************************************************************
 * You shouldn't edit below here unless you know you need to.
 *******************************************************************/

#define DROPBEAR_VERSION "0.25"
#define LOCAL_IDENT "SSH-2.0-dropbear_" DROPBEAR_VERSION

/* Time to wait before sending reply on fail */
#define FAIL_SLEEP_TIME 2

/* Timeouts in seconds */
#define SELECT_TIMEOUT 20
/* Spec recommends after one hour or 1 gigabyte of data */
#define KEX_REKEY_TIMEOUT 3600
#define KEX_REKEY_DATA (1<<30) /* 2^30 == 1GB, this value must be < INT_MAX */
/* Close connections to clients which haven't authorised after AUTH_TIMEOUT */
#define AUTH_TIMEOUT 600 /* 10 minutes is recommended */

/* various algorithm identifiers */
#define DROPBEAR_KEX_DH_GROUP1 0

#define DROPBEAR_SIGNKEY_ANY 0
#define DROPBEAR_SIGNKEY_RSA 1
#define DROPBEAR_SIGNKEY_DSS 2

#define DROPBEAR_COMP_NONE 0
#define DROPBEAR_COMP_ZLIB 1

/* Required for pubkey auth */
#ifdef DROPBEAR_PUBKEY_AUTH
#define DROPBEAR_SIGNKEY_VERIFY
#endif

/* SHA1 is 20 bytes == 160 bits */
#define SHA1_HASH_SIZE 20
/* SHA512 is 64 bytes == 512 bits */
#define SHA512_HASH_SIZE 64


#define MAX_KEY_LEN 24 /* 3DES requires a 24 byte key */
#define MAX_IV_LEN 20 /* must be same as max blocksize, 
						 and >= SHA1_HASH_SIZE */
#define MAX_MAC_KEY 20

#define MAX_NAME_LEN 64 /* maximum length of a protocol name, isn't
						   explicitly specified for all protocols (just
						   for algos) but seems valid */

#define MAX_PROPOSED_ALGO 20

/* size/count limits */
#define MAX_LISTEN_ADDR 10

#define MAX_PACKET_LEN 35000
#define MIN_PACKET_LEN 16
#define MAX_PAYLOAD_LEN 32768

#define MAX_TRANS_PAYLOAD_LEN 32768
#define MAX_TRANS_PACKET_LEN (MAX_TRANS_PAYLOAD_LEN+50)

#define MAX_TRANS_WINDOW 500000000 /* 500MB is sufficient, stopping overflow */
#define MAX_TRANS_WIN_INCR 500000000 /* overflow prevention */

#define MAX_BANNER_SIZE 2000 /* this is 25*80 chars, any more is foolish */

#define DEV_RANDOM "/dev/random"

/* the number of NAME=VALUE pairs to malloc for environ, if we don't have
 * the clearenv() function */
#define ENV_SIZE 100

#define MAX_CMD_LEN 1024 /* max length of a command */
#define MAX_TERM_LEN 200 /* max length of TERM name */

#define _PATH_TTY "/dev/tty"

#endif /* _OPTIONS_H_ */
