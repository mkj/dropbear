#ifndef DBMALLOC_H_
#define DBMALLOC_H_

#include "includes.h"

void * m_malloc(size_t size);
void * m_calloc(size_t nmemb, size_t size);
void * m_strdup(const char * str);
void * m_realloc(void* ptr, size_t size);
void m_free_direct(void* ptr);
#define m_free(X) do {m_free_direct(X); (X) = NULL;} while (0)

void m_malloc_set_epoch(unsigned int epoch);
void m_malloc_free_epoch(unsigned int epoch, int dofree);

#endif /* DBMALLOC_H_ */
