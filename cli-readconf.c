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

#if DROPBEAR_DEFAULT_USE_SSH_CONFIG

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
} CfgOption;

static struct {
	const char *name;
	CfgOption option;
} ConfigOptions[] =
{
	/* Start of config section. */
	{ "host", opHost },

	{ "hostname", opHostName },
	{ "port", opHostPort },
	{ "user", opLoginUser },
	{ "identityfile", opIdentityFile },

	/* End loop condintion. */
	{ NULL, opInvalid },
};

void read_config_file(char* filename, FILE* configFile, cli_runopts* options)
{
	DEBUG1(("Reading configuration data '%.200s'", filename));

	char *line = NULL;
	size_t linesize = 0;
	int linenum = 0;

	char* cfgKey;
	char* cfgVal;
	char* saveptr;

	int inHostSection = 0;
	while(-1 != getline(&line, &linesize, configFile))
	{
		/* Update line number counter. */
		linenum++;

		char* commentStart = strchr(line, '#');
		if(NULL != commentStart)
		{
			*commentStart = '\0'; /* Drop the comments. */
		}

		cfgKey = strtok_r(line, TOKEN_CHARS, &saveptr);
		if(NULL == cfgKey)
		{
			continue;
		}

		CfgOption cfgOpt = opInvalid;
		for (int i = 0; ConfigOptions[i].name; i++)
		{
			if (0 == strcasecmp(cfgKey, ConfigOptions[i].name))
			{
				cfgOpt = ConfigOptions[i].option;
				break;
			}
		}

		if(opInvalid == cfgOpt)
		{
			dropbear_exit("Unhandled key %s at '%s':%d.", cfgKey, filename, linenum);
		}


		cfgVal = strtok_r(NULL, TOKEN_CHARS, &saveptr);
		if(NULL == cfgVal)
		{
			dropbear_exit("Missing value for key %s at '%s':%d.", cfgKey, filename, linenum);
		}

		if(inHostSection)
		{
			if(opHost == cfgOpt)
			{
				/* Hit the next host section. Done reading config. */
				break;
			}
			switch(cfgOpt)
			{
				case opHostName:
				{
					/* The host name is the alias given on the command line.
					 * Set the actual remote host specified in the config.
					 */
					options->remotehost = strdup(cfgVal);
					options->remotehostfixed = 1; /* Subsequent command line parsing should leave it alone. */
					break;
				}

				case opHostPort:
				{
					options->remoteport = strdup(cfgVal);
					break;
				}

				case opLoginUser:
				{
					options->username = strdup(cfgVal);
					break;
				}

				case opIdentityFile:
				{
#if DROPBEAR_CLI_PUBKEY_AUTH
					char* keyFilePath;
					if(strncmp(cfgVal, "~/", 2) == 0)
					{
						keyFilePath = expand_homedir_path(cfgVal);
					}
					else if(cfgVal[0] != '/')
					{
						char* configDir = dirname(filename);
						int pathLen = strlen(configDir) + strlen(cfgVal) + 10;
						char cbuff[pathLen];
						snprintf(cbuff, pathLen, "%s/%s", configDir, cfgVal);
						keyFilePath = strdup(cbuff);
					}
					else
					{
						keyFilePath = strdup(cfgVal);
					}
					loadidentityfile(keyFilePath, 1);
					free(keyFilePath);
#else
					dropbear_exit("This version of the code does not support identity file. %s at '%s':%d.", cfgKey, filename, linenum);
#endif
					break;
				}

				default:
				{
					dropbear_exit("Unsupported configuration option %s at '%s':%d.", cfgKey, filename, linenum);
				}
			}
		}
		else
		{
			if(opHost != cfgOpt || 0 != strcmp(cfgVal, options->remotehost))
			{
				/* Not our host section. */
				continue;
			}
			inHostSection = 1;
		}
	}

	free(line);
}

#endif /* DROPBEAR_DEFAULT_USE_SSH_CONFIG */