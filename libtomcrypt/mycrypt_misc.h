/* ---- BASE64 Routines ---- */
#ifdef BASE64
extern int base64_encode(const unsigned char *in,  unsigned long len, 
                               unsigned char *out, unsigned long *outlen);

extern int base64_decode(const unsigned char *in,  unsigned long len, 
                               unsigned char *out, unsigned long *outlen);
#endif

/* ---- MEM routines ---- */
extern void zeromem(void *dst, size_t len);
extern void burn_stack(unsigned long len);

/* ch1-01-1*/
extern const char *error_to_string(int err);
/* ch1-01-1*/

extern const char *crypt_build_settings;
