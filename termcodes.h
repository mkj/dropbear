#ifndef _TERMCODES_H_
#define _TERMCODES_H_

#define TERMCODE_NONE 0
#define TERMCODE_CONTROL 1
#define TERMCODE_INPUT 2
#define TERMCODE_OUTPUT 3
#define TERMCODE_LOCAL 4
#define TERMCODE_CONTROLCHAR 5

#define MAX_TERMCODE 93

struct TermCode {

	unsigned int mapcode;
	unsigned char type;

};

const extern struct TermCode termcodes[];

#endif /* _TERMCODES_H_ */
