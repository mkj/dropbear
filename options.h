/* Dropbear SSH
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved. See LICENSE for the license. */

#ifndef _OPTIONS_H_
#define _OPTIONS_H_

/******************************************************************
 * Define compile-time options below - the "#ifndef DROPBEAR_XXX .... #endif"
 * parts are to allow for commandline -DDROPBEAR_XXX options etc.
 ******************************************************************/

#ifndef DROPBEAR_DEFPORT
#define DROPBEAR_DEFPORT "22"
#endif

#ifndef DROPBEAR_DEFADDRESS
/* Listen on all interfaces */
#define DROPBEAR_DEFADDRESS ""
#endif

/* Default hostkey paths - these can be specified on the command line */
#ifndef DSS_PRIV_FILENAME
#define DSS_PRIV_FILENAME "/etc/dropbear/dropbear_dss_host_key"
#endif
#ifndef RSA_PRIV_FILENAME
#define RSA_PRIV_FILENAME "/etc/dropbear/dropbear_rsa_host_key"
#endif

/* Set NON_INETD_MODE if you require daemon functionality (ie Dropbear listens
 * on chosen ports and keeps accepting connections. This is the default.
 *
 * Set INETD_MODE if you want to be able to run Dropbear with inetd (or
 * similar), where it will use stdin/stdout for connections, and each process
 * lasts for a single connection. Dropbear should be invoked with the -i flag
 * for inetd, and can only accept IPv4 connections.
 *
 * Both of these flags can be defined at once, don't compile without at least
 * one of them. */
#define NON_INETD_MODE
#define INETD_MODE

/* Setting this disables the fast exptmod bignum code. It saves ~5kB, but is
 * perhaps 20% slower for pubkey operations (it is probably worth experimenting
 * if you want to use this) */
/*#define NO_FAST_EXPTMOD*/

/* Set this if you want to use the DROPBEAR_SMALL_CODE option. This can save
several kB in binary size, however will make the symmetrical ciphers (AES, DES
etc) slower (perhaps by 50%). Recommended for most small systems. */
#define DROPBEAR_SMALL_CODE

/* Enable X11 Forwarding - server only */
#define ENABLE_X11FWD

/* Enable TCP Fowarding */
/* 'Local' is "-L" style (client listening port forwarded via server)
 * 'Remote' is "-R" style (server listening port forwarded via client) */

#define ENABLE_CLI_LOCALTCPFWD
#define ENABLE_CLI_REMOTETCPFWD

#define ENABLE_SVR_LOCALTCPFWD
#define ENABLE_SVR_REMOTETCPFWD

/* Enable Authentication Agent Forwarding - server only for now */
#define ENABLE_AGENTFWD

/* Encryption - at least one required.
 * RFC Draft requires 3DES and recommends AES128 for interoperability.
 * Including multiple keysize variants the same cipher 
 * (eg AES256 as well as AES128) will result in a minimal size increase.*/
#define DROPBEAR_AES128_CBC
#define DROPBEAR_3DES_CBC
#define DROPBEAR_AES256_CBC
#define DROPBEAR_BLOWFISH_CBC
#define DROPBEAR_TWOFISH256_CBC
#define DROPBEAR_TWOFISH128_CBC

/* Message Integrity - at least one required.
 * RFC Draft requires sha1 and recommends sha1-96.
 * sha1-96 may be of use for slow links, as it has a smaller overhead.
 *
 * Note: there's no point disabling sha1 to save space, since it's used
 * for the random number generator and public-key cryptography anyway.
 * Disabling it here will just stop it from being used as the integrity portion
 * of the ssh protocol.
 *
 * These hashes are also used for public key fingerprints in logs.
 * If you disable MD5, Dropbear will fall back to SHA1 fingerprints,
 * which are not the standard form. */
#define DROPBEAR_SHA1_HMAC
#define DROPBEAR_SHA1_96_HMAC
#define DROPBEAR_MD5_HMAC

/* Hostkey/public key algorithms - at least one required, these are used
 * for hostkey as well as for verifying signatures with pubkey auth.
 * Removing either of these won't save very much space.
 * SSH2 RFC Draft requires dss, recommends rsa */
#define DROPBEAR_RSA
#define DROPBEAR_DSS

/* RSA can be vulnerable to timing attacks which use the time required for
 * signing to guess the private key. Blinding avoids this attack, though makes
 * signing operations slightly slower. */
#define RSA_BLINDING

/* Define DSS_PROTOK to use PuTTY's method of generating the value k for dss,
 * rather than just from the random byte source. Undefining this will save you
 * ~4k in binary size with static uclibc, but your DSS hostkey could be exposed
 * if the random number source isn't good. In general this isn't required */
/* #define DSS_PROTOK */

/* Whether to do reverse DNS lookups. */
#define DO_HOST_LOOKUP

/* Whether to print the message of the day (MOTD). This doesn't add much code
 * size */
#define DO_MOTD

/* The MOTD file path */
#ifndef MOTD_FILENAME
#define MOTD_FILENAME "/etc/motd"
#endif

/* Authentication Types - at least one required.
   RFC Draft requires pubkey auth, and recommends password */

/* Note: PAM auth is quite simple, and only works for PAM modules which just do
 * a simple "Login: " "Password: " (you can edit the strings in svr-authpam.c).
 * It's useful for systems like OS X where standard password crypts don't work,
 * but there's an interface via a PAM module - don't bother using it otherwise.
 * You can't enable both PASSWORD and PAM. */

#define ENABLE_SVR_PASSWORD_AUTH
/*#define ENABLE_SVR_PAM_AUTH */ /* requires ./configure --enable-pam */
#define ENABLE_SVR_PUBKEY_AUTH

#define ENABLE_CLI_PASSWORD_AUTH
#define ENABLE_CLI_PUBKEY_AUTH
#define ENABLE_CLI_INTERACT_AUTH

/* This variable can be used to set a password for client
 * authentication on the commandline. Beware of platforms
 * that don't protect environment variables of processes etc. Also
 * note that it will be provided for all "hidden" client-interactive
 * style prompts - if you want something more sophisticated, use 
 * SSH_ASKPASS instead. Comment out this var to remove this functionality.*/
#define DROPBEAR_PASSWORD_ENV "DROPBEAR_PASSWORD"

/* Define this (as well as ENABLE_CLI_PASSWORD_AUTH) to allow the use of
 * a helper program for the ssh client. The helper program should be
 * specified in the SSH_ASKPASS environment variable, and dbclient
 * should be run with DISPLAY set and no tty. The program should
 * return the password on standard output */
/*#define ENABLE_CLI_ASKPASS_HELPER*/

/* Random device to use - define either DROPBEAR_RANDOM_DEV or
 * DROPBEAR_PRNGD_SOCKET.
 * DROPBEAR_RANDOM_DEV is recommended on hosts with a good /dev/(u)random,
 * otherwise use run prngd (or egd if you want), specifying the socket. 
 * The device will be queried for a few dozen bytes of seed a couple of times
 * per session (or more for very long-lived sessions). */

/* We'll use /dev/urandom by default, since /dev/random is too much hassle.
 * If system developers aren't keeping seeds between boots nor getting
 * any entropy from somewhere it's their own fault. */
#define DROPBEAR_RANDOM_DEV "/dev/urandom"

/* prngd must be manually set up to produce output */
/*#define DROPBEAR_PRNGD_SOCKET "/var/run/dropbear-rng"*/

/* Specify the number of clients we will allow to be connected but
 * not yet authenticated. After this limit, connections are rejected */
/* The first setting is per-IP, to avoid denial of service */
#ifndef MAX_UNAUTH_PER_IP
#define MAX_UNAUTH_PER_IP 5
#endif

/* And then a global limit to avoid chewing memory if connections 
 * come from many IPs */
#ifndef MAX_UNAUTH_CLIENTS
#define MAX_UNAUTH_CLIENTS 30
#endif

/* Maximum number of failed authentication tries (server option) */
#ifndef MAX_AUTH_TRIES
#define MAX_AUTH_TRIES 10
#endif

/* The default file to store the daemon's process ID, for shutdown
   scripts etc. This can be overridden with the -P flag */
#ifndef DROPBEAR_PIDFILE
#define DROPBEAR_PIDFILE "/var/run/dropbear.pid"
#endif

/* The command to invoke for xauth when using X11 forwarding.
 * "-q" for quiet */
#ifndef XAUTH_COMMAND
#define XAUTH_COMMAND "/usr/X11R6/bin/xauth -q"
#endif

/* if you want to enable running an sftp server (such as the one included with
 * OpenSSH), set the path below. If the path isn't defined, sftp will not
 * be enabled */
#ifndef SFTPSERVER_PATH
#define SFTPSERVER_PATH "/usr/libexec/sftp-server"
#endif

/* This is used by the scp binary when used as a client binary. If you're
 * not using the Dropbear client, you'll need to change it */
#define _PATH_SSH_PROGRAM "/usr/bin/dbclient"

/* Whether to log commands executed by a client. This only logs the 
 * (single) command sent to the server, not what a user did in a 
 * shell/sftp session etc. */
/* #define LOG_COMMANDS */

/* Window size limits. These tend to be a trade-off between memory
   usage and network performance: */
/* Size of the network receive window. This amount of memory is allocated
   as a per-channel receive buffer. Increasing this value can make a
   significant difference to network performance. 24kB was empirically
   chosen for a 100mbit ethernet network. The value can be altered at
   runtime with the -W argument. */
#define DEFAULT_RECV_WINDOW 24576
/* Maximum size of a received SSH data packet - this _MUST_ be >= 32768
   in order to interoperate with other implementations */
#define RECV_MAX_PAYLOAD_LEN 32768
/* Maximum size of a transmitted data packet - this can be any value,
   though increasing it may not make a significant difference. */
#define TRANS_MAX_PAYLOAD_LEN 16384

/* Ensure that data is transmitted every KEEPALIVE seconds. This can
be overridden at runtime with -K. 0 disables keepalives */
#define DEFAULT_KEEPALIVE 0

/*******************************************************************
 * You shouldn't edit below here unless you know you need to.
 *******************************************************************/

#ifndef DROPBEAR_VERSION
#define DROPBEAR_VERSION "0.50"
#endif

#define LOCAL_IDENT "SSH-2.0-dropbear_" DROPBEAR_VERSION
#define PROGNAME "dropbear"

/* Spec recommends after one hour or 1 gigabyte of data. One hour
 * is a bit too verbose, so we try 8 hours */
#ifndef KEX_REKEY_TIMEOUT
#define KEX_REKEY_TIMEOUT (3600 * 8)
#endif
#ifndef KEX_REKEY_DATA
#define KEX_REKEY_DATA (1<<30) /* 2^30 == 1GB, this value must be < INT_MAX */
#endif
/* Close connections to clients which haven't authorised after AUTH_TIMEOUT */
#ifndef AUTH_TIMEOUT
#define AUTH_TIMEOUT 300 /* we choose 5 minutes */
#endif

/* Minimum key sizes for DSS and RSA */
#ifndef MIN_DSS_KEYLEN
#define MIN_DSS_KEYLEN 512
#endif
#ifndef MIN_RSA_KEYLEN
#define MIN_RSA_KEYLEN 512
#endif

#define MAX_BANNER_SIZE 2000 /* this is 25*80 chars, any more is foolish */
#define MAX_BANNER_LINES 20 /* How many lines the client will display */

/* the number of NAME=VALUE pairs to malloc for environ, if we don't have
 * the clearenv() function */
#define ENV_SIZE 100

#define MAX_CMD_LEN 1024 /* max length of a command */
#define MAX_TERM_LEN 200 /* max length of TERM name */

#define MAX_HOST_LEN 254 /* max hostname len for tcp fwding */
#define MAX_IP_LEN 15 /* strlen("255.255.255.255") == 15 */

#define DROPBEAR_MAX_PORTS 10 /* max number of ports which can be specified,
								 ipv4 and ipv6 don't count twice */

/* Each port might have at least a v4 and a v6 address */
#define MAX_LISTEN_ADDR (DROPBEAR_MAX_PORTS*3)

#define _PATH_TTY "/dev/tty"

#define _PATH_CP "/bin/cp"

/* success/failure defines */
#define DROPBEAR_SUCCESS 0
#define DROPBEAR_FAILURE -1

/* various algorithm identifiers */
#define DROPBEAR_KEX_DH_GROUP1 0

#define DROPBEAR_SIGNKEY_ANY 0
#define DROPBEAR_SIGNKEY_RSA 1
#define DROPBEAR_SIGNKEY_DSS 2
#define DROPBEAR_SIGNKEY_NONE 3

#define DROPBEAR_COMP_NONE 0
#define DROPBEAR_COMP_ZLIB 1

/* Required for pubkey auth */
#if defined(ENABLE_SVR_PUBKEY_AUTH) || defined(DROPBEAR_CLIENT)
#define DROPBEAR_SIGNKEY_VERIFY
#endif

/* SHA1 is 20 bytes == 160 bits */
#define SHA1_HASH_SIZE 20
/* SHA512 is 64 bytes == 512 bits */
#define SHA512_HASH_SIZE 64
/* MD5 is 16 bytes = 128 bits */
#define MD5_HASH_SIZE 16

/* largest of MD5 and SHA1 */
#define MAX_MAC_LEN SHA1_HASH_SIZE


#define MAX_KEY_LEN 32 /* 256 bits for aes256 etc */
#define MAX_IV_LEN 20 /* must be same as max blocksize, 
						 and >= SHA1_HASH_SIZE */
#define MAX_MAC_KEY 20

#define MAX_NAME_LEN 64 /* maximum length of a protocol name, isn't
						   explicitly specified for all protocols (just
						   for algos) but seems valid */

#define MAX_PROPOSED_ALGO 20

/* size/count limits */
#define MIN_PACKET_LEN 16

#define RECV_MAX_PACKET_LEN (MAX(35000, ((RECV_MAX_PAYLOAD_LEN)+100)))

/* for channel code */
#define TRANS_MAX_WINDOW 500000000 /* 500MB is sufficient, stopping overflow */
#define TRANS_MAX_WIN_INCR 500000000 /* overflow prevention */

#define RECV_WINDOWEXTEND (opts.recv_window / 3) /* We send a "window extend" every
								RECV_WINDOWEXTEND bytes */
#define MAX_RECV_WINDOW (1024*1024) /* 1 MB should be enough */

#define MAX_CHANNELS 100 /* simple mem restriction, includes each tcp/x11
							connection, so can't be _too_ small */

#define MAX_STRING_LEN 1400 /* ~= MAX_PROPOSED_ALGO * MAX_NAME_LEN, also
							   is the max length for a password etc */

/* For a 4096 bit DSS key, empirically determined */
#define MAX_PUBKEY_SIZE 1700
/* For a 4096 bit DSS key, empirically determined */
#define MAX_PRIVKEY_SIZE 1700

/* The maximum size of the bignum portion of the kexhash buffer */
/* Sect. 8 of the transport draft, K_S + e + f + K */
#define KEXHASHBUF_MAX_INTS (1700 + 130 + 130 + 130)

#define DROPBEAR_MAX_SOCKS 2 /* IPv4, IPv6 are all we'll get for now. Revisit
								in a few years time.... */

#define DROPBEAR_MAX_CLI_PASS 1024

#define DROPBEAR_MAX_CLI_INTERACT_PROMPTS 80 /* The number of prompts we'll 
												accept for keyb-interactive
												auth */

#if defined(DROPBEAR_AES256_CBC) || defined(DROPBEAR_AES128_CBC)
#define DROPBEAR_AES_CBC
#endif

#if defined(DROPBEAR_TWOFISH256_CBC) || defined(DROPBEAR_TWOFISH128_CBC)
#define DROPBEAR_TWOFISH_CBC
#endif

#ifndef ENABLE_X11FWD
#define DISABLE_X11FWD
#endif

#ifndef ENABLE_AGENTFWD
#define DISABLE_AGENTFWD
#endif

#if defined(ENABLE_CLI_REMOTETCPFWD) || defined(ENABLE_CLI_LOCALTCPFWD)
#define ENABLE_CLI_ANYTCPFWD 
#endif

#if defined(ENABLE_CLI_LOCALTCPFWD) || defined(ENABLE_SVR_REMOTETCPFWD)
#define DROPBEAR_TCP_ACCEPT
#endif

#if defined(ENABLE_CLI_REMOTETCPFWD) || defined(ENABLE_CLI_LOCALTCPFWD) || \
	defined(ENABLE_SVR_REMOTETCPFWD) || defined(ENABLE_SVR_LOCALTCPFWD) || \
	defined(ENABLE_AGENTFWD) || defined(ENABLE_X11FWD)
#define USING_LISTENERS
#endif

#if defined(DROPBEAR_CLIENT) || defined(ENABLE_SVR_PUBKEY_AUTH)
#define DROPBEAR_KEY_LINES /* ie we're using authorized_keys or known_hosts */
#endif

#if defined(ENABLE_SVR_PASSWORD_AUTH) && defined(ENABLE_SVR_PAM_AUTH)
#error "You can't turn on PASSWORD and PAM auth both at once. Fix it in options.h"
#endif

#if defined(DROPBEAR_RANDOM_DEV) && defined(DROPBEAR_PRNGD_SOCKET)
#error "You can't turn on DROPBEAR_PRNGD_SOCKET and DROPBEAR_RANDOM_DEV at once"
#endif

#if !defined(DROPBEAR_RANDOM_DEV) && !defined(DROPBEAR_PRNGD_SOCKET)
#error "You must choose one of DROPBEAR_PRNGD_SOCKET or DROPBEAR_RANDOM_DEV in options.h"
#endif

/* We use dropbear_client and dropbear_server as shortcuts to avoid redundant
 * code, if we're just compiling as client or server */
#if defined(DROPBEAR_SERVER) && defined(DROPBEAR_CLIENT)

#define IS_DROPBEAR_SERVER (ses.isserver == 1)
#define IS_DROPBEAR_CLIENT (ses.isserver == 0)

#elif defined(DROPBEAR_SERVER)

#define IS_DROPBEAR_SERVER 1
#define IS_DROPBEAR_CLIENT 0

#elif defined(DROPBEAR_CLIENT)

#define IS_DROPBEAR_SERVER 0
#define IS_DROPBEAR_CLIENT 1

#else
#error You must compiled with either DROPBEAR_CLIENT or DROPBEAR_SERVER selected
#endif

#endif /* _OPTIONS_H_ */
