#ifndef DROPBEAR_LOCALOPTIONS_H
#define DROPBEAR_LOCALOPTIONS_H_
/*
  Local options override those in default_options.h for ESP Linux
  revised 9/3/19 by Brent Roman, brent@mbari.org
*/
#define DROPBEAR_VERSION "2019.78-mbari2"

//do not disallow core dumps!
#define ALLOW_COREDUMPS 1

/* Set this if you want to use the DROPBEAR_SMALL_CODE option. This can save
 * several kB in binary size however will make the symmetrical ciphers and hashes
 * slower, perhaps by 50%. Recommended for small systems that aren't doing
 * much traffic. */
#define DROPBEAR_SMALL_CODE 0

/* RSA must be >=1024 */
 //2048bit keys take up to 20minutes to generate on slow ARM9 processors!
#define DROPBEAR_DEFAULT_RSA_SIZE 1024

/* Disable X11 Forwarding */
#define DROPBEAR_X11FWD 0

/* Enable the NONE CIPHER for use when encrpytion isn't needed */
#define DROPBEAR_NONE_CIPHER 1

/* Save a network roundtrip by sending a real auth request immediately after
 * sending a query for the available methods. This is not yet enabled by default 
 since it could cause problems with non-compliant servers */ 
#define DROPBEAR_CLI_IMMEDIATE_AUTH 1

#endif /* DROPBEAR_LOCALOPTIONS_H_ */
