/*
 * auth_mysql.c: authenticate users against a MySQL database
 *
 * The only subtlety here is that the config directives for the database
 * (password etc.) are privileged information, which must be cleared prior to
 * forking after which the program could be attached to a debugger by a
 * malicious user. In fact, we zero the information at point of attaching to
 * the database.
 * 
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

#ifdef AUTH_MYSQL
static const char rcsid[] = "$Id$";

#include <sys/types.h> /* BSD needs this here, apparently. */

#include <grp.h>
#include <pwd.h>
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "auth_mysql.h"
#include "authswitch.h"
#include "md5.h"
#include "stringmap.h"
#include "util.h"

MYSQL *mysql;

/* strclr:
 * Clear a string.
 */
static void strclr(char *s) {
    char *p = s;
    while (*p) *p++ = 0;
}

/* auth_mysql_init:
 * Initialise the database connection driver. Clears the config directives
 * associated with the database so that a user cannot recover them with a
 * debugger.
 */
extern stringmap config;

int auth_mysql_init() {
    char *username = NULL, *password = NULL, *hostname = NULL, *database = NULL, *localhost = "localhost";
    item *I;
    int ret = 0;

    if ((I = stringmap_find(config, "auth-mysql-username"))) username = (char*)I->v;
    else {
        print_log(LOG_ERR, "auth_mysql_init: no auth-mysql-username directive in config");
        goto fail;
    }

    if ((I = stringmap_find(config, "auth-mysql-password"))) password = (char*)I->v;
    else {
        print_log(LOG_ERR, "auth_mysql_init: no auth-mysql-password directive in config");
        goto fail;
    }

    if ((I = stringmap_find(config, "auth-mysql-database"))) database = (char*)I->v;
    else {
        print_log(LOG_ERR, "auth_mysql_init: no auth-mysql-database directive in config");
        goto fail;
    }

    if ((I = stringmap_find(config, "auth-mysql-hostname"))) hostname = (char*)I->v;
    else hostname = localhost;

    mysql = mysql_init(NULL);
    if (!mysql) {
        print_log(LOG_ERR, "auth_mysql_init: mysql_init: failed");
        goto fail;
    }

    if (mysql_real_connect(mysql, hostname, username, password, database, 0, NULL, 0) != mysql) {
        print_log(LOG_ERR, "auth_mysql_init: mysql_real_connect: %s", mysql_error(mysql));
        mysql_close(mysql);
        mysql = NULL;
        goto fail;
    }

    ret = 1;

fail:
    if (username) strclr(username);
    if (password) strclr(password);
    if (hostname && hostname != localhost) strclr(hostname);
    if (database) strclr(database);

    return ret;
}

/* auth_mysql_new_apop:
 * Attempt to authenticate a user via APOP, using a SELECT statement of the
 * form
 *   SELECT domain.path, popbox.mbox_name, domain.unix_user,
 *          popbox.apop_password
 *           FROM popbox, domain
 *          WHERE popbox.local_part = $local_part
 *            AND popbox.domain_name = $domain
 *            AND popbox.domain_name = domain.domain_name
 */
const char apop_query_template[] =
    "SELECT domain.path, popbox.mbox_name, domain.unix_user, popbox.apop_password "
      "FROM popbox, domain "
     "WHERE popbox.local_part = '%s' "
       "AND popbox.domain_name = '%s' "
       "AND popbox.domain_name = domain.domain_name";
authcontext auth_mysql_new_apop(const char *name, const char *timestamp, const unsigned char *digest) {
    char *query, *x, *y;
    authcontext a = NULL;
    char *local_part;
    const char *domain;
    item *I;
    int use_gid = 0;
    size_t l;
    gid_t gid;

    if (!mysql) return NULL;

    /* Obtain gid to use */
    if ((I = stringmap_find(config, "auth-mysql-mail-group"))) {
        gid = atoi((char*)I->v);
        if (!gid) {
            struct group *grp;
            grp = getgrnam((char*)I->v);
            if (!grp) {
                print_log(LOG_ERR, "auth_mysql_new_apop: auth-mysql-mail-group directive `%s' does not make sense", (char*)I->v);
                return NULL;
            }
            gid = grp->gr_gid;
        }
        use_gid = 1;
    }
#ifdef AUTH_MYSQL_MAIL_GID
    else {
        gid = AUTH_PAM_MAIL_GID;
        use_gid = 1;
    }
#endif

    domain = name + strcspn(name, "@%!");
    if (domain == name || !*domain) return NULL;
    ++domain;
    
    local_part = (char*)malloc(domain - name);
    if (!local_part) return NULL;
    memset(local_part, 0, domain - name);
    strncpy(local_part, name, domain - name - 1);
    
    if (mysql_ping(mysql) == -1) {
        print_log(LOG_ERR, "auth_mysql_new_apop: mysql_ping: %s", mysql_error(mysql));
        return NULL;
    }

    query = (char*)malloc(l = (sizeof(apop_query_template) + strlen(name) * 2 + 1));
    x = (char*)malloc(strlen(local_part) * 2 + 1);
    y = (char*)malloc(strlen(domain) * 2 + 1);
    if (!query || !x || !y) goto fail;

    mysql_escape_string(x, local_part, strlen(local_part));
    mysql_escape_string(y, domain, strlen(domain));

    snprintf(query, l, apop_query_template, x, y);

    if (mysql_query(mysql, query) == 0) {
        MYSQL_RES *result = mysql_store_result(mysql);
        int i;

        if (!result) {
            print_log(LOG_ERR, "auth_mysql_new_apop: mysql_store_result: %s", mysql_error(mysql));
            goto fail;
        }

        switch (i = mysql_num_rows(result)) {
        case 0:
            print_log(LOG_WARNING, "auth_mysql_new_apop: attempted login by nonexistent user %s@%s", local_part, domain);
            break;
        case 1: {
                MYSQL_ROW row = mysql_fetch_row(result);
                unsigned long *lengths;
                char *mailbox;
                struct passwd *pw;
                unsigned char this_digest[16];
                MD5_CTX ctx;

                /* These are "can't happen" errors */
                if (!row || !(lengths = mysql_fetch_lengths(result))) break;
                
                /* Calculate our idea of the digest */
                MD5Init(&ctx);
                MD5Update(&ctx, (unsigned char*)timestamp, strlen(timestamp));
                MD5Update(&ctx, (unsigned char*)row[3], lengths[3]);
                MD5Final(this_digest, &ctx);

                /* User was lying */
                if (memcmp(this_digest, digest, 16)) {
                    print_log(LOG_WARNING, "auth_mysql_new_apop: failed login for %s@%s", local_part, domain);
                    break;
                }

                /* User was not lying (about her password) */
                pw = getpwnam((const char*)row[2]);

                if (!pw) {
                    print_log(LOG_ERR, "auth_mysql_new_apop: getpwnam(%s): %m", (const char*)row[2]);
                    break;
                }

                /* It would be bad to allow a virtual domain user to log in as
                 * root....
                 */
                if (!pw->pw_uid) {
                    print_log(LOG_ERR, "auth_mysql_new_apop: unix user for domain is root");
                    break;
                }

                mailbox = (char*)malloc(l = (lengths[0] + lengths[1] + 2));
                snprintf(mailbox, l, "%s/%s", row[0], row[1]);

                a = authcontext_new(pw->pw_uid,
                                    use_gid ? gid : pw->pw_gid,
                                    mailbox);

                free(mailbox);

		break;
            }

        default:
            print_log(LOG_ERR, "auth_mysql_new_apop: database inconsistency: query for %s returned %d rows", name, i);
            break;
        }

        mysql_free_result(result);
        
    } else {
        print_log(LOG_ERR, "auth_mysql_new_apop: mysql_query: %s", mysql_error(mysql));
    }

fail:
    if (local_part) free(local_part);
    if (x) free(x);
    if (y) free(y);
    if (query) free(query);

    return a;
}

/* auth_mysql_new_user_pass:
 * Attempt to authenticate a user via USER/PASS, using a SELECT statement of
 * the form
 *   SELECT domain.path, popbox.mbox_name, domain.unix_user
 *          FROM popbox, domain
 *          WHERE popbox.local_part = $local_part
 *            AND popbox.password_hash = $hash_of_password
 *            AND popbox.domain_name = $domain
 *            AND popbox.domain_name = domain.domain_name
 */
char user_pass_query_template[] =
    "SELECT domain.path, popbox.mbox_name, domain.unix_user "
      "FROM popbox, domain "
     "WHERE popbox.local_part = '%s' "
       "AND popbox.domain_name = '%s' "
       "AND popbox.password_hash = '%s' "
       "AND popbox.domain_name = domain.domain_name";
authcontext auth_mysql_new_user_pass(const char *user, const char *pass) {
    char *query, *x, *y;
    authcontext a = NULL;
    char *local_part;
    const char *domain;
    unsigned char digest[16];
    char hexdigest[33] = {0};
    char *p;
    unsigned char *q;
    MD5_CTX ctx;
    item *I;
    size_t l;
    int use_gid = 0;
    gid_t gid;

    if (!mysql) return NULL;

    /* Obtain gid to use */
    if ((I = stringmap_find(config, "auth-mysql-mail-group"))) {
        gid = atoi((char*)I->v);
        if (!gid) {
            struct group *grp;
            grp = getgrnam((char*)I->v);
            if (!grp) {
                print_log(LOG_ERR, "auth_mysql_new_user_pass: auth-mysql-mail-group directive `%s' does not make sense", (char*)I->v);
                return NULL;
            }
            gid = grp->gr_gid;
        }
        use_gid = 1;
    }
#ifdef AUTH_PAM_MAIL_GID
    else {
        gid = AUTH_PAM_MAIL_GID;
        use_gid = 1;
    }
#endif
    
    domain = user + strcspn(user, "@%!");
    if (domain == user || !*domain) return NULL;
    ++domain;
    
    local_part = (char*)malloc(domain - user);
    if (!local_part) return NULL;
    memset(local_part, 0, domain - user);
    strncpy(local_part, user, domain - user - 1);
    
    if (mysql_ping(mysql) == -1) {
        print_log(LOG_ERR, "auth_mysql_new_user_pass: mysql_ping: %s", mysql_error(mysql));
        return NULL;
    }

    query = (char*)malloc(l = (sizeof(user_pass_query_template) + strlen(user) * 2 + 1 + 34));
    x = (char*)malloc(strlen(local_part) * 2 + 1);
    y = (char*)malloc(strlen(domain) * 2 + 1);
    if (!query || !x || !y) goto fail;

    MD5Init(&ctx);
    MD5Update(&ctx, (unsigned char*)pass, strlen(pass));
    MD5Final(digest, &ctx);

    for (p = hexdigest, q = digest; q < digest + 16; ++q, p += 2) snprintf(p, 3, "%02x", (unsigned)*q);

    mysql_escape_string(x, local_part, strlen(local_part));
    mysql_escape_string(y, domain, strlen(domain));

    snprintf(query, l, user_pass_query_template, x, y, hexdigest);

    if (mysql_query(mysql, query) == 0) {
        MYSQL_RES *result = mysql_store_result(mysql);
        int i;

        if (!result) {
            print_log(LOG_ERR, "auth_mysql_new_user_pass: mysql_store_result: %s", mysql_error(mysql));
            goto fail;
        }

        switch (i = mysql_num_rows(result)) {
        case 0:
            print_log(LOG_WARNING, "auth_mysql_new_user_pass: failed login for %s@%s", local_part, domain);
            break;
        case 1: {
                MYSQL_ROW row = mysql_fetch_row(result);
                unsigned long *lengths;
                char *mailbox;
                struct passwd *pw;

                /* These are "can't happen" errors */
                if (!row || !(lengths = mysql_fetch_lengths(result))) break;
                
                pw = getpwnam((const char*)row[2]);

                if (!pw) {
                    print_log(LOG_ERR, "auth_mysql_new_user_pass: getpwnam(%s): %m", (const char*)row[2]);
                    break;
                }

                /* It would be bad to allow a virtual domain user to log in as
                 * root....
                 */
                if (!pw->pw_uid) {
                    print_log(LOG_ERR, "auth_mysql_new_user_pass: unix user for domain is root");
                    break;
                }

                mailbox = (char*)malloc(l = (lengths[0] + lengths[1] + 2));
                snprintf(mailbox, l, "%s/%s", row[0], row[1]);

                a = authcontext_new(pw->pw_uid,
                                    use_gid ? gid : pw->pw_gid,
                                    mailbox);

                free(mailbox);

		break;
            }

        default:
            print_log(LOG_ERR, "auth_mysql_new_user_pass: database inconsistency: query for %s@%s returned %d rows", local_part, domain, i);
            break;
        }

        mysql_free_result(result);
        
    } else {
        print_log(LOG_ERR, "auth_mysql_new_user_pass: mysql_query: %s", mysql_error(mysql));
    }

fail:
    if (local_part) free(local_part);
    if (x) free(x);
    if (y) free(y);
    if (query) free(query);

    return a;
}

/* auth_mysql_close:
 * Close the database connection.
 */
void auth_mysql_close() {
    if (mysql) mysql_close(mysql);
}

#endif /* AUTH_MYSQL */
