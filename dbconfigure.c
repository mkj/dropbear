#include "dbconfigure.h"

static int check_line_limit(const char *config_file, int line_length, int line_count);
static void free_config_file(config_file_content *self);
static config_file_content *init_config_file_content(void);

static int check_line_limit(const char *config_file, int line_length, int line_count)
{
	if (line_length > CONFIG_FILE_LINE_MAX_LENGTH) {
		fprintf(stderr, "[%s] line length too long\n", config_file);
		return -1;
	}
	if (line_count > CONFIG_FILE_MAX_LINE) {
		fprintf(stderr, "[%s] too many lines_count\n", config_file);
		return -1;
	}
	return 0;
}

static void free_config_file(config_file_content *self)
{
	int i;
	
	if (self) {
		if (self->lines) {
			for (i = 0; i < self->lines_count; i++)
				if (self->lines[i])
					free(self->lines[i]);		
			free(self->lines);
		}
		free(self);
	}
}

static config_file_content *init_config_file_content(void)
{
	config_file_content *content;
	
	content = (config_file_content*) m_malloc(sizeof(config_file_content));
	content->free = free_config_file;
	
	return content;
}

config_file_content *read_config_file(const char *config_file)
{
	char content[CONFIG_FILE_CONTENT_SIZE] = {'\0'};
	char buf[512];
	config_file_content *cfc = NULL;
	int fd, ret, len;
	unsigned int i, j, count = 0;
	
	if ((fd = open(config_file, O_RDONLY)) == -1)
		return NULL;
	
	while ((ret = read(fd, buf, sizeof(buf))) > 0) {
		if (count + ret >= sizeof(content)) {
			fprintf(stderr, "config file %s too large\n", config_file);
			close(fd);
			return NULL;
		}
		memcpy(&content[count], buf, ret);
		count += ret;
	}

	cfc = init_config_file_content();
	cfc->lines = (char**) m_malloc(CONFIG_FILE_MAX_LINE * sizeof(char*));
	cfc->lines_count = 0;
	for (i = 0, j = 0; i < count; i++) {
		if (content[i] == '\n') {
			if (i == 0) {  /* some '\n' before text, eat them. */
				while (i < count - 1 && content[i + 1] == '\n')
					i++;
				j = i + 1;  /* let j point to a character after '\n' */
				continue;
			}
			if (check_line_limit(config_file, i - j + 1, cfc->lines_count + 1) != 0)
				goto error_free;
			cfc->lines[cfc->lines_count++] = (char*) m_malloc((i - j + 1) * sizeof(char));
			memcpy(cfc->lines[cfc->lines_count - 1], &content[j], i - j);
			cfc->lines[cfc->lines_count - 1][i - j] = '\0';
			while (i < count - 1 && content[i + 1] == '\n')
				i++;  /* eat '\n' after a line */
			j = i + 1;
		} else if (content[i] == '#') {
			unsigned int pre_i = i;
			while (i < count - 1) {
				if (content[i + 1] != '\n' && content[i + 1] != '#' && content[i] == '\n')
					break;
				else
					i++;  /* eat comment */
			}
			if (pre_i != j) {  /* comment after text in one line, ie: abcd #comment */
				if (check_line_limit(config_file, pre_i - j + 1, cfc->lines_count + 1) != 0)
					goto error_free;
				cfc->lines[cfc->lines_count++] = (char*) m_malloc((pre_i - j + 1) * sizeof(char));
				memcpy(cfc->lines[cfc->lines_count - 1], &content[j], pre_i - j);
				cfc->lines[cfc->lines_count - 1][pre_i - j] = '\0';					
			}
			if (i == count - 1)  /* reach end */
				break;
			else
				j = i + 1;
		} else if (i == count - 1) {			
			if (check_line_limit(config_file, i - j + 2, cfc->lines_count + 1) != 0)
				goto error_free;
			cfc->lines[cfc->lines_count++] = (char*) m_malloc((i - j + 2) * sizeof(char));
			memcpy(cfc->lines[cfc->lines_count - 1], &content[j], i - j + 1);
			cfc->lines[cfc->lines_count - 1][i + 1] = '\0';
			break;
		}

		if (lines_cnt > 1) {
			len = strlen(lines[lines_cnt - 1]);

			if (len >= 1 && lines[lines_cnt - 1][len - 1] == '\r') {
				lines[lines_cnt - 1][len - 1] = '\0';
			}
		}		
	}
	
	if (cfc->lines_count == 0) {
		goto error_free;
	} else {
		close(fd);
		return cfc;
	}
	
error_free:
	cfc->free(cfc);
	close(fd);
	return NULL;
}

