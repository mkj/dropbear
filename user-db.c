#include "user-db.h"
#include <pwd.h>
#include <stdlib.h>
#include <error.h>
#include "dbutil.h"

#define DB_KEY      "cppcoffee@gmail.com"


bool get_db_default_path(char* path, size_t len) {
    size_t wd_len;
    struct passwd* result = NULL;

    if ((result = getpwuid(getuid())) == NULL) {
        fprintf(stderr, "getpwuid getpwnam_r(%d): %s\n", getuid(), strerror(errno));
        return false;
    }

    wd_len = strlen(result->pw_dir);
    strncpy(path, result->pw_dir, wd_len > len ? len : wd_len);
    strcat(path, "/.dropbear/user.db");
    return true;
}

bool db_init(user_db* db_info) {
    char* dir_name;
    char dir_path[PATH_MAX];

    const char *cli_db_sql =
            "CREATE TABLE IF NOT EXISTS session_db ("
            "id INTEGER PRIMARY KEY ASC,"
            "session_name TEXT,"
            "host VARCHAR(255),"
            "port INTEGER,"
            "username VARCHAR(255),"
            "password TEXT"
            ");";

    bzero(db_info, sizeof(*db_info));
    if (!get_db_default_path(db_info->path, sizeof(db_info->path))) {
        return false;
    }
    memcpy(dir_path, db_info->path, sizeof(db_info->path));
    if ((dir_name = dirname(dir_path)) == NULL) {
        fprintf(stderr, "db_info dirname fail: %s\n", strerror(errno));
        return false;
    }

    if (0 != access(dir_name, F_OK)) {
        if (0 != mkdir(dir_name, 666)) {
            fprintf(stderr, "db_info mkdir(%s) fail: %s\n",
                    dir_name, strerror(errno));
        }
    }

    int rc = sqlite3_open(db_info->path, &db_info->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_init open(%s) fail: %s\n",
                db_info->path, sqlite3_errmsg(db_info->db));
        return false;
    }

    rc = sqlite3_key(db_info->db, DB_KEY, sizeof(DB_KEY));
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_init set key fail: %s\n", sqlite3_errmsg(db_info->db));
        sqlite3_close(db_info->db);
        return false;
    }
    char* errmsg;
    rc = sqlite3_exec(db_info->db, cli_db_sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_info create table fail: %s\n", errmsg);
        sqlite3_free(errmsg);
    }
    return true;
}


char* db_get_passwd_by_session_name(user_db* db_info, const char *session_name) {
    sqlite3_stmt* stmt;
    const char *sql = "SELECT password FROM session_db "
                "WHERE session_name=:session_name;";

    int rc = sqlite3_prepare_v2(db_info->db, sql, strlen(sql), &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_get_pass prepare_v2 rc(%d): %s\n", rc, sqlite3_errmsg(db_info->db));
        return NULL;
    }

    char* result = NULL;
    sqlite3_bind_text(stmt, 1, session_name, strlen(session_name), NULL);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        result = m_strdup((char*)sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);
    return result;
}

void db_update_info(user_db* db_info, char* session_name, char* remotehost,
        char* remoteport, char* username, char* password) {
    char* old_pw = db_get_passwd_by_session_name(db_info, session_name);
    if (old_pw == NULL) {
        db_insert(db_info, session_name, remotehost, remoteport, username, password);
    } else {
        if (strcmp(old_pw, password) != 0) {
            db_update_passwd_by_session_name(db_info, session_name);
        }
        m_free(old_pw);
    }
}


bool db_insert(user_db* db_info, char* session_name, char* remotehost,
        char* remoteport, char* username, char* password) {
    sqlite3_stmt *stmt;
    const char* ins_sql = "INSERT INTO session_db (session_name, host, port, username, password) "
                "VALUES (:session_name, :host, :port, :username, :password);";

    int rc = sqlite3_prepare_v2(db_info->db, ins_sql, strlen(ins_sql), &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_insert prepare_v2 error: %s\n", sqlite3_errmsg(db_info->db));
        return false;
    }

    sqlite3_bind_text(stmt, 1, session_name, strlen(session_name), NULL);
    sqlite3_bind_text(stmt, 2, remotehost, strlen(remotehost), NULL);
    sqlite3_bind_text(stmt, 3, remoteport, strlen(remoteport), NULL);
    sqlite3_bind_text(stmt, 4, username, strlen(username), NULL);
    sqlite3_bind_text(stmt, 5, password, strlen(password), NULL);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        printf("db_insert rc(%d): %s\n", rc, sqlite3_errmsg(db_info->db));
    }

    sqlite3_finalize(stmt);
    return true;
}


bool db_update_passwd_by_session_name(user_db* db_info, const char* session_name) {
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE session_db SET password=:password "
            "WHERE session_name=:session_name;";
    int rc = sqlite3_prepare_v2(db_info->db, sql, strlen(sql), &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_update_pw prepare_v2 error: %s\n", sqlite3_errmsg(db_info->db));
        return false;
    }

    sqlite3_bind_text(stmt, 1, session_name, strlen(session_name), NULL);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        fprintf(stderr, "db_update_pw: %s\n", sqlite3_errmsg(db_info->db));
        return false;
    }
    return true;
}

void db_print_server_lists(user_db* db_info, FILE* fp) {
    sqlite3_stmt *stmt;
    const char* sql = "select * from session_db;";
    int rc = sqlite3_prepare_v2(db_info->db, sql, strlen(sql), &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_print_server_lists prepare_v2 error: %s\n", sqlite3_errmsg(db_info->db));
        return;
    }

    fprintf(fp, "id\tsession_name\t\thost\t\tport\tuser\tpassword\n");
    fprintf(fp, "------  ----------------------  --------------  ------  ------  -------------\n");
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int i;
        int count = sqlite3_data_count(stmt);
        for (i = 0; i < count; i++) {
            switch (sqlite3_column_type(stmt, i)) {
            case SQLITE3_TEXT:
                fprintf(fp, "%s", sqlite3_column_text(stmt, i));
                break;
            case SQLITE_INTEGER:
                fprintf(fp, "%d", sqlite3_column_int(stmt, i));
                break;
            }
            fprintf(fp, "\t");
        }
        fprintf(fp, "\n");
    }
    sqlite3_finalize(stmt);
}

bool db_delete_by_session_name(user_db* db_info, const char* session_name) {
    sqlite3_stmt* stmt;
    const char* sql = "DELETE FROM session_db WHERE session_name = :session_name;";

    int rc = sqlite3_prepare_v2(db_info->db, sql, strlen(sql), &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_delete_by_session_name prepare_v2 error: %s\n", sqlite3_errmsg(db_info->db));
        return false;
    }
    sqlite3_bind_text(stmt, 1, session_name, strlen(session_name), NULL);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

void db_clean(user_db* db_info) {
    if (db_info == NULL || db_info->db == NULL)
        return;

    sqlite3_free(db_info->db);
    db_info->db = NULL;
    bzero(db_info, sizeof(*db_info));
}

