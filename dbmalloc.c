#include "dbmalloc.h"
#include "dbutil.h"

#define LIST_SIZE 1000

struct dbmalloc_header {
    unsigned int index;
    unsigned int epoch;
};

static struct dbmalloc_header* dbmalloc_list[LIST_SIZE];

unsigned int current_epoch = 0;

void m_malloc_set_epoch(unsigned int epoch) {
    current_epoch = epoch;
}

void m_malloc_free_epoch(unsigned int epoch) {
    unsigned int i;
    unsigned int freed = 0;
    for (i = 0; i < LIST_SIZE; i++) {
        if (dbmalloc_list[i] != NULL) {
            assert(dbmalloc_list[i]->index == i);
            if (dbmalloc_list[i]->epoch == epoch) {
                free(dbmalloc_list[i]);
                dbmalloc_list[i] = NULL;
                freed++;
            }
        }
    }
    TRACE(("free_epoch freed %d", freed))
}

static void put_alloc(struct dbmalloc_header *header) {
    unsigned int i;
    for (i = 0; i < LIST_SIZE; i++) {
        if (dbmalloc_list[i] == NULL) {
            dbmalloc_list[i] = header;
            header->index = i;
            return;
        }
    }
    dropbear_exit("ran out of dbmalloc entries");
}

static void remove_alloc(struct dbmalloc_header *header) {
    assert(header->index < LIST_SIZE);
    assert(dbmalloc_list[header->index] == header);
    assert(header->epoch == current_epoch);
    dbmalloc_list[header->index] = NULL;
}

static struct dbmalloc_header* get_header(void* ptr) {
    char* bptr = ptr;
    return (struct dbmalloc_header*)&bptr[-sizeof(struct dbmalloc_header)];
}

void * m_malloc(size_t size) {
    char* mem = NULL;
    struct dbmalloc_header* header = NULL;

    if (size == 0 || size > 1e9) {
        dropbear_exit("m_malloc failed");
    }

    size = size + sizeof(struct dbmalloc_header);

    mem = calloc(1, size);
    if (mem == NULL) {
        dropbear_exit("m_malloc failed");
    }
    header = (struct dbmalloc_header*)mem;
    put_alloc(header);
    header->epoch = current_epoch;
    return &mem[sizeof(struct dbmalloc_header)];
}

void * m_calloc(size_t nmemb, size_t size) {
    assert(nmemb <= 1000 && size <= 10000);
    return m_malloc(nmemb*size);
}

void * m_realloc(void* ptr, size_t size) {
    char* mem = NULL;
    struct dbmalloc_header* header = NULL;
    if (size == 0 || size > 1e9) {
        dropbear_exit("m_realloc failed");
    }

    header = get_header(ptr);
    remove_alloc(header);

    size = size + sizeof(struct dbmalloc_header);
    mem = realloc(header, size);
    if (mem == NULL) {
        dropbear_exit("m_realloc failed");
    }

    header = (struct dbmalloc_header*)mem;
    put_alloc(header);
    return &mem[sizeof(struct dbmalloc_header)];
}

void m_free_direct(void* ptr) {
    struct dbmalloc_header* header = NULL;
    if (!ptr) {
        return;
    }
    header = get_header(ptr);
    remove_alloc(header);
    free(header);
}

void * m_strdup(const char * str) {
    char* ret;
    unsigned int len;
    len = strlen(str);

    ret = m_malloc(len+1);
    if (ret == NULL) {
        dropbear_exit("m_strdup failed");
    }
    memcpy(ret, str, len+1);
    return ret;
}


