#ifndef DROPBEAR_DBCTYPE_H_
#define DROPBEAR_DBCTYPE_H_

/* Locale-independent replacements for the <ctype.h> character
   classification functions. The standard ones have undefined behaviour
   when passed a plain char with a value that doesn't fit in unsigned
   char, and their results can vary with locale. Dropbear only cares
   about ASCII ranges, so simple comparisons suffice. Bytes outside
   0-127 never match. */

/* c89 has no "inline" keyword. gcc and clang accept __inline__ in
   any mode; otherwise fall back to plain static functions. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define DBCTYPE_INLINE static inline
#elif defined(__GNUC__)
#define DBCTYPE_INLINE static __inline__
#else
#define DBCTYPE_INLINE static
#endif

DBCTYPE_INLINE int ascii_isdigit(char c) {
	return c >= '0' && c <= '9';
}

DBCTYPE_INLINE int ascii_isalpha(char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

DBCTYPE_INLINE int ascii_isalnum(char c) {
	return ascii_isalpha(c) || ascii_isdigit(c);
}

DBCTYPE_INLINE int ascii_isspace(char c) {
	return c == ' ' || c == '\t' || c == '\n'
		|| c == '\v' || c == '\f' || c == '\r';
}

DBCTYPE_INLINE int ascii_isprint(char c) {
	return c >= 0x20 && c <= 0x7e;
}

DBCTYPE_INLINE char ascii_tolower(char c) {
	if (c >= 'A' && c <= 'Z') {
		return c + ('a' - 'A');
	}
	return c;
}

#endif /* DROPBEAR_DBCTYPE_H_ */
