#ifndef __USER_DB_H__
#define __USER_DB_H__

#include <stdbool.h>
#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <sqlcipher/sqlite3.h>


typedef struct _user_db {
    sqlite3* db;
    char path[PATH_MAX];
} user_db;

bool db_init(user_db* db_info);
void db_clean(user_db* db_info);


void db_update_session(user_db* db_info, char* session_name, char* remotehost,
        char* remoteport, char* username, char* password);

char* db_get_passwd_by_session_name(user_db* db_info, const char *session_name);
char* db_get_session_name_by_alias(user_db* db_info, const char* alias_name);

bool db_exist_alias(user_db* db_info, const char* alias);
bool db_exist_session_name(user_db* db_info, const char* session_name);

bool db_delete_alias_name(user_db* db_info, const char* alias_name);
bool db_delete_session_name(user_db* db_info, const char* session_name);

bool db_update_session_alias(user_db* db, const char* session_name, const char* alias_name);

void db_print_server_lists(user_db* db_info, FILE* fp);


#endif
