#ifndef _RANDOM_H_
#define _RANDOM_H_

void seedrandom();
void genrandom(unsigned char* buf, int len);
void addrandom(unsigned char* buf, int len);

#endif /* _RANDOM_H_ */
