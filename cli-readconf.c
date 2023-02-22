/*
 * Dropbear - a SSH2 server
 *
 * Copyright (c) 2023 TJ Kolev
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "dbutil.h"
#include "runopts.h"

#if DROPBEAR_USE_SSH_CONFIG

#define TOKEN_CHARS " =\t\n"

#if DROPBEAR_CLI_PUBKEY_AUTH
extern void loadidentityfile(const char* filename, int warnfail);
#endif

typedef enum {
	opInvalid = -1,
	opHost,
	opHostName,
	opHostPort,
	opLoginUser,
	opIdentityFile,
} cfg_option;

static struct {
	const char *name;
	cfg_option option;
}
config_options[] = {
	/* Start of config section. */
	{ "host", opHost },

	{ "hostname", opHostName },
	{ "port", opHostPort },
	{ "user", opLoginUser },
	{ "identityfile", opIdentityFile },

	/* End loop condintion. */
	{ NULL, opInvalid },
};

void read_config_file(char* filename, FILE* config_file, cli_runopts* options) {
	DEBUG1(("Reading configuration data '%.200s'", filename));

	char *line = NULL;
	size_t linesize = 0;
	int linenum = 0;

	char* cfg_key;
	char* cfg_val;
	char* saveptr;

	int in_host_section = 0;
	while (-1 != getline(&line, &linesize, config_file)) {
		/* Update line number counter. */
		linenum++;

		char* commentStart = strchr(line, '#');
		if (NULL != commentStart) {
			*commentStart = '\0'; /* Drop the comments. */
		}

		cfg_key = strtok_r(line, TOKEN_CHARS, &saveptr);
		if (NULL == cfg_key) {
			continue;
		}

		cfg_option cfg_opt = opInvalid;
		for (int i = 0; config_options[i].name; i++) {
			if (0 == strcasecmp(cfg_key, config_options[i].name)) {
				cfg_opt = config_options[i].option;
				break;
			}
		}

		if (opInvalid == cfg_opt) {
			dropbear_exit("Unhandled key %s at '%s':%d.", cfg_key, filename, linenum);
		}


		cfg_val = strtok_r(NULL, TOKEN_CHARS, &saveptr);
		if (NULL == cfg_val) {
			dropbear_exit("Missing value for key %s at '%s':%d.", cfg_key, filename, linenum);
		}

		if (in_host_section) {
			if (opHost == cfg_opt) {
				/* Hit the next host section. Done reading config. */
				break;
			}
			switch (cfg_opt) {
				case opHostName: {
					/* The host name is the alias given on the command line.
					 * Set the actual remote host specified in the config.
					 */
					options->remotehost = strdup(cfg_val);
					options->remotehostfixed = 1; /* Subsequent command line parsing should leave it alone. */
					break;
				}

				case opHostPort: {
					options->remoteport = strdup(cfg_val);
					break;
				}

				case opLoginUser: {
					options->username = strdup(cfg_val);
					break;
				}

				case opIdentityFile: {
#if DROPBEAR_CLI_PUBKEY_AUTH
					char* key_file_path;
					if (strncmp(cfg_val, "~/", 2) == 0) {
						key_file_path = expand_homedir_path(cfg_val);
					}
					else if (cfg_val[0] != '/') {
						char* config_dir = dirname(filename);
						int path_len = strlen(config_dir) + strlen(cfg_val) + 10;
						char cbuff[path_len];
						snprintf(cbuff, path_len, "%s/%s", config_dir, cfg_val);
						key_file_path = strdup(cbuff);
					}
					else {
						key_file_path = strdup(cfg_val);
					}
					loadidentityfile(key_file_path, 1);
					free(key_file_path);
#else
					dropbear_exit("This version of the code does not support identity file. %s at '%s':%d.", cfg_key, filename, linenum);
#endif
					break;
				}

				default: {
					dropbear_exit("Unsupported configuration option %s at '%s':%d.", cfg_key, filename, linenum);
				}
			}
		}
		else
		{
			if (opHost != cfg_opt || 0 != strcmp(cfg_val, options->remotehost)) {
				/* Not our host section. */
				continue;
			}
			in_host_section = 1;
		}
	}

	free(line);
}

#endif /* DROPBEAR_USE_SSH_CONFIG */