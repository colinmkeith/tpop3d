/*
 * auth_pgsql.c:
 * Authenticate users against a Postgres database.
 *
 * XXX should have the connection retrying behaviour of auth-mysql.
 *
 * Copyright (c) 2003 Chris Lightfoot, Stephen White. All rights reserved.
 *
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_PGSQL
static const char rcsid[] = "$Id$";

#include <sys/types.h> /* BSD needs this here, apparently. */

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#include <grp.h>
#include <pwd.h>
#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "auth_pgsql.h"
#include "authswitch.h"
#include "config.h"
#include "password.h"
#include "stringmap.h"
#include "util.h"

/* 
 * Old libpq doesn't have this function....
 */
#ifndef SYSTEM_PQESCAPESTRING

/* PQescapeStringLocal TO FROM LENGTH
 * Local copy of the escape-string function which escapes dangerous characters
 * in query FROM, writing the modified string into TO. */
size_t PQescapeStringLocal(char *to, const char *from, size_t length) {
    const char *source;
    char *target;
    unsigned int remaining;

    source = from;
    target = to;
    remaining = length;

    while (remaining > 0) {
        switch (*source) {
            case '\\':
                *target = '\\';
                target++;
                *target = '\\';
                break;

            case '\'':
                *target = '\'';
                target++;
                *target = '\'';
                break;

            case '"':
                *target = '\\';
                target++;
                *target = '"';
                break;

            case '\0':
                *target = '\\';
                target++;
                *target = '0';
                break;

            default:
                *target = *source;
                break;
        }
        source++;
        target++;
        remaining--;
    }

    /* Write the terminating NUL character. */
    *target = '\0';

    return target - to;
}

#define PQescapeString(to, from, len) PQescapeStringLocal(to, from, len)

#endif /* SYSTEM_PQESCAPESTRING */

/* Default query templates. The returned fields are:
 *  [0] location of mailbox
 *  [1] password hash
 *  [2] unix user
 *  [3] mailbox type
 */
char *user_pass_query_template =
    "SELECT domain.path || '/'  || popbox.mbox_name, popbox.password_hash, "
            "domain.unix_user, 'bsd' "
      "FROM popbox, domain "
     "WHERE popbox.local_part = '$(local_part)' "
       "AND popbox.domain_name = '$(domain)' "
       "AND popbox.domain_name = domain.domain_name";
       
char *apop_query_template =
    "SELECT domain.path || '/' || popbox.mbox_name, popbox.password_hash, "
            "domain.unix_user, 'bsd' "
      "FROM popbox, domain "
     "WHERE popbox.local_part = '$(local_part)' "
       "AND popbox.domain_name = '$(domain)' "
       "AND popbox.domain_name = domain.domain_name";

char *onlogin_query_template = NULL;

/* GID used to access mail spool (if any). */
int use_gid;
gid_t mail_gid;

static char *substitute_query_params(const char *temp, const char *user, const char *local_part, const char *domain, const char *clienthost, const char *serverhost);

/* pg_strerror CONNECTION
 * Wrapper for PQerrorMessage which removes any trailing newline (aargh). */
static char *pg_strerror(const PGconn *conn) {
    static char *s;
    s = PQerrorMessage(conn);
    s[strlen(s) - 1] = 0;   /* ugh */
    return s;
}

/* strclr STRING
 * Clear the contents of STRING. */
static void strclr(char *s) {
    memset(s, 0, strlen(s));
}

/* auth_pgsql_init
 * Initialise the database connection driver. Clears the config directives
 * associated with the database so that a user cannot recover them with a
 * debugger. */
PGconn *pg_conn;

int auth_pgsql_init(void) {
    char *username = NULL, *password = NULL, *hostname = NULL, *database = NULL, *localhost = "localhost", *s;
    char *dbconnect = NULL;
    int ret = 0;

    if ((s = config_get_string("auth-pgsql-username")))
        username = s;
    else {
        log_print(LOG_ERR, _("auth_pgsql_init: no auth-pgsql-username directive in config"));
        goto fail;
    }

    if ((s = config_get_string("auth-pgsql-password")))
        password = s;
    else {
        log_print(LOG_WARNING, _("auth_pgsql_init: no auth-pgsql-password directive in config; using blank password"));
        password = "";
    }

    if ((s = config_get_string("auth-pgsql-database")))
        database = s;
    else {
        log_print(LOG_ERR, _("auth_pgsql_init: no auth-pgsql-database directive in config"));
        goto fail;
    }

    if ((s = config_get_string("auth-pgsql-hostname")))
        hostname = s;
    else hostname = localhost;

    /* Obtain query templates. The special string `none' means `don't use
     * any query for this action'. */
    if ((s = config_get_string("auth-pgsql-pass-query")))
        user_pass_query_template = s;
    if (strcmp(user_pass_query_template, "none") == 0)
        user_pass_query_template = NULL;
    
    if ((s = config_get_string("auth-pgsql-apop-query")))
        apop_query_template = s;
    if (strcmp(apop_query_template, "none") == 0)
        apop_query_template = NULL;

    /* This is an optional action to put a row into the database after a
     * successful login, for POP-before-SMTP relaying. */
    if ((s = config_get_string("auth-pgsql-onlogin-query")))
        onlogin_query_template = s;

    /* Obtain gid to use */
    if ((s = config_get_string("auth-pgsql-mail-group"))) {
        if (!parse_gid(s, &mail_gid)) {
            log_print(LOG_ERR, _("auth_pgsql_init: auth-pgsql-mail-group directive `%s' does not make sense"), s);
            goto fail;
        }
        use_gid = 1;
    }

    /* What a horrid interface.... */
    dbconnect = xmalloc(sizeof("dbname= host= user= password=") + strlen(database) + strlen(hostname) + strlen(username) + strlen(password));
    
    sprintf(dbconnect, "dbname=%s%s%s%s%s%s%s",
            database,
            hostname ? " host=" : "",
            hostname ? hostname : "",
            username ? " user=" : "",
            username ? username : "",
            password ? " password=" : "",
            password ? password : ""
        );
    
    pg_conn = PQconnectdb(dbconnect);
    if (PQstatus(pg_conn) == CONNECTION_BAD) {
        log_print(LOG_ERR, "auth_pgsql_init: PQconnectdb: failed (%s)", PQerrorMessage(pg_conn));
        goto fail;
    }

    ret = 1;

fail:
    if (username) strclr(username);
    if (password) strclr(password);
    if (hostname && hostname != localhost) strclr(hostname);
    if (database) strclr(database);
    xfree(dbconnect);

    return ret;
}

extern int verbose; /* in main.c */

/* auth_pgsql_new_apop NAME LOCAL-PART DOMAIN TIMESTAMP DIGEST CLIENTHOST SERVERHOST
 * Attempt to authenticate a user via APOP, using the template SELECT query in
 * the config file or the default defined above otherwise. */
authcontext auth_pgsql_new_apop(const char *name, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost /* unused */, const char *serverhost) {
    char *query = NULL;
    authcontext a = NULL;
    char *who;
    PGresult *res = NULL;

    who = username_string(name, local_part, domain);

    if (!pg_conn || !apop_query_template) return NULL;

    /* Obtain the actual query to use. */
    if (!(query = substitute_query_params(apop_query_template, name, local_part, domain, NULL, serverhost)))
        goto fail;

    if (verbose)
        log_print(LOG_DEBUG, "auth_pgsql_new_apop: SQL query: %s", query);

    if ((res = PQexec(pg_conn, query))) {
        int i;

        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            log_print(LOG_ERR, "auth_pgsql_new_apop: error executing query: %s", PQresultErrorMessage(res));
            goto fail;
        }

        if (PQnfields(res) != 4) {
            log_print(LOG_ERR, "auth_pgsql_new_apop: %d fields returned by query, should be 4: mailbox location, password hash, unix user, mailbox type", PQnfields(res));
            goto fail;
        }

        switch (i = PQntuples(res)) {
        case 0:
            break;
        case 1: {
                uid_t uid;
                struct passwd *pw;
                char *user, *passwd, *mailbox, *mboxdrv;

                /* Check that user has UID and password. */
                if (PQgetisnull(res, 0, 2)) {
                    log_print(LOG_ERR, _("auth_pgsql_new_apop: UID for user %s is NULL"), who);
                    goto fail;
                } else if (PQgetisnull(res, 0, 1)) {
                    log_print(LOG_ERR, _("auth_pgsql_new_apop: password hash for user %s is NULL"), who);
                    goto fail;
                }

                /* Get the various fields. */
                passwd = PQgetvalue(res, 0, 1);
                user = PQgetvalue(res, 0, 2);
                
                mailbox = PQgetisnull(res, 0, 0) ? NULL : PQgetvalue(res, 0, 0);
                mboxdrv = PQgetisnull(res, 0, 3) ? NULL : PQgetvalue(res, 0, 3);
                    
                if (!check_password_apop(who, passwd, timestamp, digest)) {
                    log_print(LOG_WARNING, _("auth_pgsql_new_apop: failed login for %s"), who);
                    goto fail;
                }

                /* User was not lying (about her password) */
                if (!parse_uid(user, &uid)) {
                    log_print(LOG_ERR, _("auth_pgsql_new_apop: unix user `%s' for %s does not make sense"), user, who);
                    break;
                }

                pw = getpwuid(uid);

                if (!pw) {
                    log_print(LOG_ERR, "auth_pgsql_apop: getpwuid(%d): %m", (int)uid);
                    break;
                }

                a = authcontext_new(pw->pw_uid, use_gid ? mail_gid : pw->pw_gid, mboxdrv, mailbox, pw->pw_dir);

                break;
            }

        default:
            log_print(LOG_ERR, _("auth_pgsql_new_apop: database inconsistency: query for %s returned %d rows"), name, i);
            break;
        }

        PQclear(res);
    } else
        log_print(LOG_ERR, _("auth_pgsql_new_apop: PQexec: %s"), pg_strerror(pg_conn));

fail:
    xfree(query);
    
    return a;
}

/* auth_pgsql_new_user_pass USER LOCAL-PART DOMAIN PASSWORD CLIENTHOST SERVERHOST
 * Attempt to authenticate a user via USER/PASS, using the template SELECT
 * query in the config file or the default defined above otherwise. */
authcontext auth_pgsql_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost /* unused */, const char *serverhost) {
    char *query = NULL, *who;
    authcontext a = NULL;
    PGresult *res = NULL;

    who = username_string(user, local_part, domain);
    
    if (!pg_conn || !user_pass_query_template) return NULL;

    /* Obtain the actual query to use. */
    if (!(query = substitute_query_params(user_pass_query_template, user, local_part, domain, NULL, serverhost)))
        goto fail;

    if (verbose)
        log_print(LOG_DEBUG, "auth_pgsql_new_user_pass: SQL query: %s", query);

    if ((res = PQexec(pg_conn, query))) {
        int i;

        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            log_print(LOG_ERR, "auth_pgsql_new_user_pass: error executing query: %s", PQresultErrorMessage(res));
            goto fail;
        }

        if (PQnfields(res) != 4) {
            log_print(LOG_ERR, "auth_pgsql_new_user_pass: %d fields returned by query, should be 4: mailbox location, password hash, unix user, mailbox type", PQnfields(res));
            goto fail;
        }

        switch (i = PQntuples(res)) {
        case 0:
            break;
        case 1: {
                struct passwd *pw;
                uid_t uid;
                char *user, *pwhash, *mailbox, *mboxdrv;

                /* Check that user has UID and password. */
                if (PQgetisnull(res, 0, 2)) {
                    log_print(LOG_ERR, _("auth_pgsql_new_apop: UID for user %s is NULL"), who);
                    goto fail;
                } else if (PQgetisnull(res, 0, 1)) {
                    log_print(LOG_ERR, _("auth_pgsql_new_apop: password hash for user %s is NULL"), who);
                    goto fail;
                }

                /* Get the various fields. */
                pwhash = PQgetvalue(res, 0, 1);
                user = PQgetvalue(res, 0, 2);
                
                mailbox = PQgetisnull(res, 0, 0) ? NULL : PQgetvalue(res, 0, 0);
                mboxdrv = PQgetisnull(res, 0, 3) ? NULL : PQgetvalue(res, 0, 3);

                if (!check_password(who, pwhash, pass, "{md5}")) {
                    log_print(LOG_ERR, _("auth_pgsql_new_user_pass: %s failed login with wrong password"), who);
                    break;
                }

                if (!parse_uid(user, &uid)) {
                    log_print(LOG_ERR, _("auth_pgsql_new_user_pass: unix user `%s' for %s does not make sense"), user, who);
                    break;
                }

                pw = getpwuid(uid);

                if (!pw) {
                    log_print(LOG_ERR, "auth_pgsql_new_user_pass: getpwuid(%d): %m", (int)uid);
                    break;
                }

                a = authcontext_new(pw->pw_uid, use_gid ? mail_gid : pw->pw_gid, mboxdrv, mailbox, pw->pw_dir);
                break;
            }

        default:
            log_print(LOG_ERR, _("auth_pgsql_new_user_pass: database inconsistency: query for %s returned %d rows"), who, i);
            break;
        }

        PQclear(res);
    } else
        log_print(LOG_ERR, _("auth_pgsql_new_apop: PQexec: %s"), pg_strerror(pg_conn));

fail:
    xfree(query);

    return a;
}

/* auth_pgsql_onlogin AUTHCONTEXT CLIENTHOST SERVERHOST
 * If specified, perform a query (action) after a successful login. The
 * variables substituted in the template are $(local_part), $(domain) and
 * $(clienthost), the username, domain, and connecting client host. */
void auth_pgsql_onlogin(const authcontext A, const char *clienthost, const char *serverhost) {
    char *query;
    PGresult *res = NULL;

    if (!pg_conn || !onlogin_query_template) return;

    query = substitute_query_params(onlogin_query_template, A->user, A->local_part, A->domain, clienthost, serverhost);
    if (!query)
        return;

    if (verbose)
        log_print(LOG_DEBUG, _("auth_pgsql_onlogin: SQL query: %s"), query);

    if ((res = PQexec(pg_conn, query))) { /* XXX transactions? */
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            log_print(LOG_ERR, "auth_pgsql_onlogin: bad status after PQexec: %s", pg_strerror(pg_conn));
        } else if (PQntuples(res)) {
          /* It's possible that the user put a query in which returned some rows
           * This is bogus but there's not a lot we can do */
            log_print(LOG_WARNING, _("auth_pgsql_onlogin: supplied SQL query returned %d rows, which is dubious"), PQntuples(res));
        }
        PQclear(res);
    } else
        log_print(LOG_ERR, _("auth_pgsql_onlogin: PQexec: %s"), pg_strerror(pg_conn));

    xfree(query);
}

/* auth_pgsql_postfork
 * Post-fork cleanup. */
void auth_pgsql_postfork(void) {
    pg_conn = NULL;
}

/* auth_pgsql_close
 * Close the database connection. */
void auth_pgsql_close(void) {
    if (pg_conn) PQfinish(pg_conn);
}

/* substitute_query_params TEMPLATE USER LOCAL-PART DOMAIN CLIENTHOST SERVERHOST
 * Given a query template, a localpart and a domain, return a copy of the
 * template with the fields filled in. */
static char *substitute_query_params(const char *template, const char *user, const char *local_part, const char *domain, const char *clienthost, const char *serverhost) {
    char *query, *u = NULL, *l = NULL, *d = NULL, *c = NULL, *s = NULL;
    struct sverr err;

    /* Form escaped copies of the user and domain. 
     * The terminating null is added but not counted in the to_length */
    u = xmalloc(strlen(user) * 2 + 1);
    PQescapeString(u,user,strlen(user));
    
    if (local_part) {
        l = xmalloc(strlen(local_part) * 2 + 1);
        PQescapeString(l, local_part, strlen(local_part));
    }

    if (domain) {
        d = xmalloc(strlen(domain) * 2 + 1);
        PQescapeString(d, domain, strlen(domain));
    }

    if (clienthost) {
        c = xmalloc(strlen(clienthost) * 2 + 1);
        PQescapeString(c, clienthost, strlen(clienthost));
    }

    if (serverhost) {
        s = xmalloc(strlen(serverhost) * 2 + 1);
        PQescapeString(s, serverhost, strlen(serverhost));
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

#endif /* AUTH_PGSQL */
