/*
 * auth_mysql.c:
 * Authenticate users against a MySQL database.
 *
 * Copyright (c) 2001 Chris Lightfoot.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_MYSQL
static const char rcsid[] = "$Id$";

#include <sys/types.h> /* BSD needs this here, apparently. */

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#include <grp.h>
#include <pwd.h>
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "auth_mysql.h"
#include "authswitch.h"
#include "config.h"
#include "md5.h"
#include "password.h"
#include "stringmap.h"
#include "util.h"
#include "tokenise.h"

/* 
 * Default query templates. The returned fields are:
 *  [0] location of mailbox
 *  [1] password hash
 *  [2] unix user
 *  [3] mailbox type
 */
static char *user_pass_query_template =
    "SELECT concat(domain.path, '/', popbox.mbox_name), popbox.password_hash, "
            "domain.unix_user, 'bsd' "
      "FROM popbox, domain "
     "WHERE popbox.local_part = '$(local_part)' "
       "AND popbox.domain_name = '$(domain)' "
       "AND popbox.domain_name = domain.domain_name";
       
static char *apop_query_template =
    "SELECT concat(domain.path, '/', popbox.mbox_name), popbox.password_hash, "
            "domain.unix_user, 'bsd' "
      "FROM popbox, domain "
     "WHERE popbox.local_part = '$(local_part)' "
       "AND popbox.domain_name = '$(domain)' "
       "AND popbox.domain_name = domain.domain_name";

static char *onlogin_query_template = NULL;

/* GID used to access mail spool (if any). */
static int use_gid;
static gid_t mail_gid;

static char *substitute_query_params(const char *temp, const char *user, const char *local_part, const char *domain, const char *clienthost, const char *serverhost);

/*
 * Connection to the MySQL server.
 */
static MYSQL *mysql = NULL;
static tokens mysql_servers;
static char mysql_driver_active = 0;

/* get_mysql_server:
 * If we are not currently connected to a MySQL server, or if the current MySQL
 * server doesn't respond any more, try to connect to all defined MySQL
 * servers. If none work, we give up.  Return 0 if OK, -1 if we can't connect
 * to any server. */
static int get_mysql_server(void) {
    int n;
    static MYSQL mysql_handle;
    char *password;
    unsigned int timeout;
    my_bool want_reconnect = 0;

    if (mysql && mysql_ping(mysql) == 0)
        /* The current server is up and running. */
        return 0;

    if (mysql)
        /* The current server doesn't respond anymore. */
        mysql_close(mysql);

    mysql = mysql_init(&mysql_handle);

    if (!mysql) {
        log_print(LOG_ERR, _("get_mysql_server: mysql_init: failed"));
        return -1;
    }

    if (!(password = config_get_string("auth-mysql-password")))
        password = "";

    for (n = 0; n < mysql_servers->num; n++) {
       /* To prevent the main process from being blocked for too long, we set
        * the timeout when connecting to a remote mysql server to 5 seconds. Of
        * course you need to have a network fast enough to allow TCP
        * connections to the mysql servers to be started in less than 5
        * seconds.... */
        timeout = 5;
        mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (char*)&(timeout));

#ifdef MYSQL_OPT_RECONNECT
	/* We do not want automatic reconnect to happen. */
	mysql_options(mysql, MYSQL_OPT_RECONNECT, &want_reconnect);
#endif

        if (mysql_real_connect(mysql, mysql_servers->toks[n],
                config_get_string("auth-mysql-username"),
                password,
                config_get_string("auth-mysql-database"),
                0, NULL, 0) != mysql) {
            log_print(LOG_WARNING, "get_mysql_server: server %s: %s", mysql_servers->toks[n], mysql_error(mysql));
            continue;
        }

        log_print(LOG_DEBUG, _("get_mysql_server: now using server %s"), mysql_servers->toks[n]);
        return 0;
    }

    log_print(LOG_ERR, _("get_mysql_server: can't find any working MySQL server; giving up"));

    mysql = NULL;

    return -1;
}

/* auth_mysql_init:
 * Initialise the database connection driver. */
int auth_mysql_init() {
    char *hostname = NULL, *localhost = "localhost", *s;

    if (!config_get_string("auth-mysql-username")) {
        log_print(LOG_ERR, _("auth_mysql_init: no auth-mysql-username directive in config"));
        return 0;
    }

    if (!config_get_string("auth-mysql-password")) {
        log_print(LOG_WARNING, _("auth_mysql_init: no auth-mysql-password directive in config; using blank password"));
    }

    if (!config_get_string("auth-mysql-database")) {
        log_print(LOG_ERR, _("auth_mysql_init: no auth-mysql-database directive in config"));
        return 0;
    }

    if ((s = config_get_string("auth-mysql-hostname")))
        hostname = s;
    else hostname = localhost;

    /* Obtain query templates. The special string `none' means `don't use
     * any query for this action'. */
    if ((s = config_get_string("auth-mysql-pass-query")))
        user_pass_query_template = s;
    if (strcmp(user_pass_query_template, "none") == 0)
        user_pass_query_template = NULL;

    if ((s = config_get_string("auth-mysql-apop-query")))
        apop_query_template = s;
    if (strcmp(apop_query_template, "none") == 0)
        apop_query_template = NULL;

    /* This is an optional action to put a row into the database after a
     * successful login, for POP-before-SMTP relaying. */
    if ((s = config_get_string("auth-mysql-onlogin-query")))
        onlogin_query_template = s;

    /* Obtain gid to use */
    if ((s = config_get_string("auth-mysql-mail-group"))) {
        if (!parse_gid(s, &mail_gid)) {
            log_print(LOG_ERR, _("auth_mysql_init: auth-mysql-mail-group directive `%s' does not make sense"), s);
            return 0;
        }
        use_gid = 1;
    }

    mysql_servers = tokens_new(hostname, " \t");

    if (get_mysql_server() == -1) {
        /* No server has been found working. */
        tokens_delete(mysql_servers);
        log_print(LOG_ERR, _("auth_mysql_init: aborting"));
        return 0;
    }

    mysql_driver_active = 1;

    return 1;
}

extern int verbose; /* in main.c */

/* auth_mysql_new_apop:
 * Attempt to authenticate a user via APOP, using the template SELECT query in
 * the config file or the default defined above otherwise. */
authcontext auth_mysql_new_apop(const char *name, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost /* unused */, const char *serverhost) {
    char *query = NULL;
    authcontext a = NULL;
    char *who;

    who = username_string(name, local_part, domain);

    if (!mysql_driver_active || !apop_query_template) return NULL;

    if (get_mysql_server() == -1) {
        log_print(LOG_ERR, _("auth_mysql_new_apop: aborting"));
        return NULL;
    }

    /* Obtain the actual query to use. */
    if (!(query = substitute_query_params(apop_query_template, name, local_part, domain, NULL, serverhost)))
        goto fail;

    if (verbose)
        log_print(LOG_DEBUG, _("auth_mysql_new_apop: SQL query: %s"), query);

    if (mysql_query(mysql, query) == 0) {
        MYSQL_RES *result;
        int i;

        result = mysql_store_result(mysql);
        if (!result) {
            log_print(LOG_ERR, "auth_mysql_new_apop: mysql_store_result: %s", mysql_error(mysql));
            goto fail;
        }

        if (mysql_field_count(mysql) != 4) {
            log_print(LOG_ERR, _("auth_mysql_new_apop: %d fields returned by query, should be 4: mailbox location, password hash, unix user, mailbox type"), mysql_field_count(mysql));
            goto fail;
        }

        switch (i = mysql_num_rows(result)) {
        case 0:
            break;
        case 1: {
                MYSQL_ROW row;
                unsigned long *lengths;
                struct passwd *pw;
                uid_t uid;
                
                row = mysql_fetch_row(result);
                /* These are "can't happen" errors */
                if (!row || !(lengths = mysql_fetch_lengths(result))) break;

                /* Sanity check. Verify that user has UID and password. */
                if (!row[2]) {
                    log_print(LOG_ERR, _("auth_mysql_new_apop: UID for user %s is NULL"), who);
                    goto fail;
                } else if (!row[1]) {
                    log_print(LOG_ERR, _("auth_mysql_new_apop: password hash for user %s is NULL"), who);
                    goto fail;
                }
 
                /* Actually check the password. */
                if (!check_password_apop(who, row[1], timestamp, digest)) {
                    log_print(LOG_WARNING, _("auth_mysql_new_apop: failed login for %s"), who);
                    break;
                }

                /* User was not lying (about her password) */
                if (!parse_uid((const char*)row[2], &uid)) {
                    log_print(LOG_ERR, _("auth_mysql_new_apop: unix user `%s' for %s does not make sense"), row[2], who);
                    break;
                }

                pw = getpwuid(uid);

                if (!pw) {
                    log_print(LOG_ERR, "auth_mysql_new_apop: getpwuid(%d): %m", (int)uid);
                    break;
                }

                a = authcontext_new(pw->pw_uid, use_gid ? mail_gid : pw->pw_gid, row[3], row[0], pw->pw_dir);

                break;
            }

        default:
            log_print(LOG_ERR, _("auth_mysql_new_apop: database inconsistency: query for %s returned %d rows, should be 0 or 1"), name, i);
            break;
        }

        mysql_free_result(result);
        
    } else
        log_print(LOG_ERR, "auth_mysql_new_apop: mysql_query: %s", mysql_error(mysql));

fail:
    if (query) xfree(query);

    return a;
}

/* auth_mysql_new_user_pass:
 * Attempt to authenticate a user via USER/PASS, using the template SELECT
 * query in the config file or the default defined above otherwise. */
authcontext auth_mysql_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost /* unused */, const char *serverhost) {
    char *query = NULL, *who;
    authcontext a = NULL;

    who = username_string(user, local_part, domain);
    
    if (!mysql_driver_active || !user_pass_query_template) return NULL;

    if (get_mysql_server() == -1) {
        log_print(LOG_ERR, _("auth_mysql_new_user_pass: aborting"));
        return NULL;
    }

    /* Obtain the actual query to use. */
    if (!(query = substitute_query_params(user_pass_query_template, user, local_part, domain, NULL, serverhost)))
        goto fail;

    if (verbose)
        log_print(LOG_DEBUG, _("auth_mysql_new_user_pass: SQL query: %s"), query);

    if (mysql_query(mysql, query) == 0) {
        MYSQL_RES *result;
        int i;

        result = mysql_store_result(mysql);
        if (!result) {
            log_print(LOG_ERR, _("auth_mysql_new_user_pass: mysql_store_result: %s"), mysql_error(mysql));
            goto fail;
        }

        if (mysql_field_count(mysql) != 4) {
            log_print(LOG_ERR, _("auth_mysql_new_user_pass: %d fields returned by query, should be 4: mailbox location, password hash, unix user, mailbox type"), mysql_field_count(mysql));
            goto fail;
        }

        switch (i = mysql_num_rows(result)) {
        case 0:
            break;
        case 1: {
                MYSQL_ROW row;
                unsigned long *lengths;
                struct passwd *pw;
                uid_t uid;
                
                row = mysql_fetch_row(result);

                /* These are "can't happen" errors */
                if (!row || !(lengths = mysql_fetch_lengths(result))) break;

                /* Sanity check. Verify that user has UID and password. */
                if (!row[2]) {
                    log_print(LOG_ERR, _("auth_mysql_new_user_pass: UID for user %s is NULL"), who);
                    goto fail;
                } else if (!row[1]) {
                    log_print(LOG_ERR, _("auth_mysql_new_user_pass: password hash for user %s is NULL"), who);
                    break;
                }

                /* Verify the password. */
                if (!check_password(who, row[1], pass, "{md5}")) {
                    log_print(LOG_ERR, _("auth_mysql_new_user_pass: %s failed login with wrong password"), who);
                    break;
                }

                if (!parse_uid((const char*)row[2], &uid)) {
                    log_print(LOG_ERR, _("auth_mysql_new_user_pass: unix user `%s' for %s does not make sense"), row[2], who);
                    break;
                }

                pw = getpwuid(uid);

                if (!pw) {
                    log_print(LOG_ERR, "auth_mysql_new_user_pass: getpwuid(%d): %m", (int)uid);
                    break;
                }

                a = authcontext_new(pw->pw_uid, use_gid ? mail_gid : pw->pw_gid, row[3], row[0], pw->pw_dir);
                break;
            }

        default:
            log_print(LOG_ERR, _("auth_mysql_new_user_pass: database inconsistency: query for %s returned %d rows, should be 0 or 1"), who, i);
            break;
        }

        mysql_free_result(result);
    } else
        log_print(LOG_ERR, "auth_mysql_new_user_pass: mysql_query: %s", mysql_error(mysql));

fail:
    xfree(query);

    return a;
}

/* auth_mysql_onlogin:
 * If specified, perform a query (action) after a successful login. The
 * variables substituted in the template are $(local_part), $(domain) and
 * $(clienthost), the username, domain, and connecting client host. */
void auth_mysql_onlogin(const authcontext A, const char *clienthost, const char *serverhost) {
    char *query;

    if (!mysql_driver_active || !onlogin_query_template) return;

    if (get_mysql_server() == -1) {
        log_print(LOG_ERR, _("auth_mysql_onlogin: aborting"));
        return;
    }

    query = substitute_query_params(onlogin_query_template, A->user, A->local_part, A->domain, clienthost, serverhost);
    if (!query)
        return;

    if (verbose)
        log_print(LOG_DEBUG, _("auth_mysql_onlogin: SQL query: %s"), query);

    if (mysql_query(mysql, query) == 0) {
        MYSQL_RES *result;
        /* It's possible that the user put a query in which returned some rows.
         * This is bogus but there's not a lot we can do; to avoid leaking
         * memory or confusing the database, we obtain and free a result, and
         * log a warning. */
        result = mysql_store_result(mysql);
        if (result) {
            log_print(LOG_WARNING, _("auth_mysql_onlogin: supplied SQL query returned %d rows, which is dubious"), mysql_num_rows(result));
            mysql_free_result(result);
        }
    } else
        log_print(LOG_ERR, "auth_mysql_onlogin: mysql_query: %s", mysql_error(mysql));

    xfree(query);
}

/* auth_mysql_postfork:
 * Post-fork cleanup. */
void auth_mysql_postfork() {
    mysql = NULL;
    mysql_driver_active = 0;
}

/* auth_mysql_close:
 * Close the database connection. */
void auth_mysql_close() {
    if (mysql) {
        mysql_close(mysql);
        mysql = NULL;
        tokens_delete(mysql_servers);
    }
}

/* substitute_query_params
 * Given a query template, a localpart and a domain, return a copy of the
 * template with the fields filled in. */
static char *substitute_query_params(const char *template, const char *user, const char *local_part, const char *domain, const char *clienthost, const char *serverhost) {
    char *query, *u = NULL, *l = NULL, *d = NULL, *c = NULL, *s = NULL;
    struct sverr err;

    /* Form escaped copies of the user and domain. */
    u = xmalloc(strlen(user) * 2 + 1);
    mysql_escape_string(u, user, strlen(user));
    
    if (local_part) {
        l = xmalloc(strlen(local_part) * 2 + 1);
        mysql_escape_string(l, local_part, strlen(local_part));
    }

    if (domain) {
        d = xmalloc(strlen(domain) * 2 + 1);
        mysql_escape_string(d, domain, strlen(domain));
    }

    if (clienthost) {
        c = xmalloc(strlen(clienthost) * 2 + 1);
        mysql_escape_string(c, clienthost, strlen(clienthost));
    }

    if (serverhost) {
        s = xmalloc(strlen(serverhost) * 2 + 1);
        mysql_escape_string(s, serverhost, strlen(serverhost));
    }

    /* Do the substitution. */
    query = substitute_variables(template, &err, 5, "user", u, "local_part", l, "domain", d, "clienthost", c, "serverhost", s);

    if (!query && err.code != sv_nullvalue)
        log_print(LOG_ERR, _("substitute_query_params: %s near `%.16s'"), err.msg, template + err.offset);

    xfree(s);
    xfree(c);
    xfree(u);
    xfree(l);
    xfree(d);
    return query;
}

#endif /* AUTH_MYSQL */
