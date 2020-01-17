#ifndef CONFIGURE_H_
#define CONFIGURE_H_

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "dbmalloc.h"


#define CONFIG_FILE_MAX_LINE  256
#define CONFIG_FILE_LINE_MAX_LENGTH  512
#define CONFIG_FILE_CONTENT_SIZE  (CONFIG_FILE_MAX_LINE * CONFIG_FILE_LINE_MAX_LENGTH)

typedef struct Config_file_content {
	char **lines;
	int lines_count;  /* exclude empty line and comment line */
	void (*free) (struct Config_file_content *self);
} config_file_content;

config_file_content *read_config_file(const char *config_file);

#endif
