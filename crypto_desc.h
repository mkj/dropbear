#ifndef DROPBEAR_CRYPTO_DESC_H
#define DROPBEAR_CRYPTO_DESC_H

void crypto_init(void);
void crypto_configure(const char *config_file);

extern int dropbear_ltc_prng;

#endif /* DROPBEAR_CRYPTO_DESC_H */

