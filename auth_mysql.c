/*
 * auth_mysql.c:
 * Authenticate users against a MySQL database.
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
#include "md5.h"
#include "stringmap.h"
#include "util.h"

/* Default query templates. The returned fields are:
 *  [0] location of mailbox
 *  [1] password hash
 *  [2] unix user
 *  [3] mailbox type
 */
char *user_pass_query_template =
    "SELECT concat(domain.path, '/', popbox.mbox_name), popbox.password_hash, "
            "domain.unix_user, 'bsd' "
      "FROM popbox, domain "
     "WHERE popbox.local_part = '$(local_part)' "
       "AND popbox.domain_name = '$(domain)' "
       "AND popbox.domain_name = domain.domain_name";
       
char *apop_query_template =
    "SELECT concat(domain.path, '/', popbox.mbox_name), popbox.password_hash, "
            "domain.unix_user, 'bsd' "
      "FROM popbox, domain "
     "WHERE popbox.local_part = '$(local_part)' "
       "AND popbox.domain_name = '$(domain)' "
       "AND popbox.domain_name = domain.domain_name";

static char *substitute_query_params(const char *temp, const char *local_part, const char *domain);

/* MD5 crypt(3) routines. This is here so that you can migrate passwords from
 * the modern /etc/shadow crypt_md5 format used (optionally) by recent
 * Linux-PAM distributions. This code was taken from Linux-PAM 0.75.
 *
 * (Note that on most Linux systems this won't be necessary, since the system
 * crypt(3) function is `smart' in the sense that it looks for a constant
 * string `$1$' at the beginning of the password hash, and if that string is
 * present, uses crypt_md5 instead of traditional crypt. However, I include
 * this function in the interests of portability and future compatibility.)
 *
 * Original author's notice:
 * 
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 */

static unsigned char itoa64[] = /* 0 ... 63 => ascii - 64 */
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* to64:
 * Convert a string into a different base.
 */
static void to64(char *s, unsigned long v, int n)
{
    while (--n >= 0) {
        *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

/* crypt_md5:
 * Poul-Henning Kamp's crypt(3)-alike using MD5.
 */
static char *crypt_md5(const char *pw, const char *salt)
{
    const char *magic = "$1$";
    /* This string is magic for this algorithm.  Having
     * it this way, we can get get better later on */
    static char passwd[120], *p;
    static const char *sp,*ep;
    unsigned char   final[16];
    int sl,pl,i,j;
    MD5_CTX ctx,ctx1;
    unsigned long l;

    /* Refine the Salt first */
    sp = salt;

    /* If it starts with the magic string, then skip that */
    if(!strncmp(sp,magic,strlen(magic)))
        sp += strlen(magic);

    /* It stops at the first '$', max 8 chars */
    for(ep=sp;*ep && *ep != '$' && ep < (sp+8);ep++)
        continue;

    /* get the length of the true salt */
    sl = ep - sp;

    MD5Init(&ctx);

    /* The password first, since that is what is most unknown */
    MD5Update(&ctx,(unsigned char *)pw,strlen(pw));

    /* Then our magic string */
    MD5Update(&ctx,(unsigned char *)magic,strlen(magic));

    /* Then the raw salt */
    MD5Update(&ctx,(unsigned char *)sp,sl);

    /* Then just as many characters of the MD5(pw,salt,pw) */
    MD5Init(&ctx1);
    MD5Update(&ctx1,(unsigned char *)pw,strlen(pw));
    MD5Update(&ctx1,(unsigned char *)sp,sl);
    MD5Update(&ctx1,(unsigned char *)pw,strlen(pw));
    MD5Final(final,&ctx1);
    for(pl = strlen(pw); pl > 0; pl -= 16)
        MD5Update(&ctx,(unsigned char *)final,pl>16 ? 16 : pl);

    /* Don't leave anything around in vm they could use. */
    memset(final,0,sizeof final);

    /* Then something really weird... */
    for (j=0,i = strlen(pw); i ; i >>= 1)
        if(i&1)
            MD5Update(&ctx, (unsigned char *)final+j, 1);
        else
            MD5Update(&ctx, (unsigned char *)pw+j, 1);

    /* Now make the output string */
    strcpy(passwd,magic);
    strncat(passwd,sp,sl);
    strcat(passwd,"$");

    MD5Final(final,&ctx);

    /*
     * and now, just to make sure things don't run too fast
     * On a 60 Mhz Pentium this takes 34 msec, so you would
     * need 30 seconds to build a 1000 entry dictionary...
     */
    for(i=0;i<1000;i++) {
        MD5Init(&ctx1);
        if(i & 1)
            MD5Update(&ctx1,(unsigned char *)pw,strlen(pw));
        else
            MD5Update(&ctx1,(unsigned char *)final,16);

        if(i % 3)
            MD5Update(&ctx1,(unsigned char *)sp,sl);

        if(i % 7)
            MD5Update(&ctx1,(unsigned char *)pw,strlen(pw));

        if(i & 1)
            MD5Update(&ctx1,(unsigned char *)final,16);
        else
            MD5Update(&ctx1,(unsigned char *)pw,strlen(pw));
        MD5Final(final,&ctx1);
    }

    p = passwd + strlen(passwd);

    l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; to64(p,l,4); p += 4;
    l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; to64(p,l,4); p += 4;
    l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; to64(p,l,4); p += 4;
    l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; to64(p,l,4); p += 4;
    l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; to64(p,l,4); p += 4;
    l =                    final[11]                ; to64(p,l,2); p += 2;
    *p = '\0';

    /* Don't leave anything around in vm they could use. */
    memset(final,0,sizeof final);

    return passwd;
}

/* MD5 crypt(3) routines end. */


/* MySQL PASSWORD() routines. This is here so that you can use the MySQL
 * proprietary password-hashing routine with tpop3d. The code is inserted here
 * to avoid having to do an explicit query to get the MySQL password hash.
 * Observe that this is not completely safe, since the machine on which the
 * MySQL server is running may use a different character set to this machine.
 * However, it is probably not worth worrying about this in reality.
 *
 * In fact, these functions will probably be available in libmysqlclient, but
 * that doesn't appear to be documented, so better safe than sorry.
 *
 * This code is taken from the MySQL distribution. The original license for
 * the code in sql/password.c states:
 *
 * Copyright Abandoned 1996 TCX DataKonsult AB & Monty Program KB & Detron HB
 * This file is public domain and comes with NO WARRANTY of any kind
 */

/* mysql_hash_password:
 * MySQL password-hashing routine. */
static void mysql_hash_password(unsigned long *result, const char *password) {
    register unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
    unsigned long tmp;
    for (; *password; password++) {
        if (*password == ' ' || *password == '\t')
            continue;			/* skip space in password */
        tmp  = (unsigned long) (unsigned char) *password;
        nr  ^= (((nr & 63) + add) * tmp) + (nr << 8);
        nr2 += (nr2 << 8) ^ nr;
        add += tmp;
    }
    result[0] =  nr & (((unsigned long) 1L << 31) -1L); /* Don't use sign bit (str2int) */;
    result[1] = nr2 & (((unsigned long) 1L << 31) -1L);
    return;
}

/* mysql_make_scrambled_password:
 * MySQL function to form a password hash and turn it into a string. */
static void mysql_make_scrambled_password(char *to, const char *password) {
    unsigned long hash_res[2];
    mysql_hash_password(hash_res, password);
    sprintf(to, "%08lx%08lx", hash_res[0], hash_res[1]);
}

/* MySQL PASSWORD() routines end. */


/* strclr:
 * Clear a string.
 */
static void strclr(char *s) {
    memset(s, 0, strlen(s));
}

/* auth_mysql_init:
 * Initialise the database connection driver. Clears the config directives
 * associated with the database so that a user cannot recover them with a
 * debugger. */
extern stringmap config; /* in main.c */
MYSQL *mysql;

int auth_mysql_init() {
    char *username = NULL, *password = NULL, *hostname = NULL, *database = NULL, *localhost = "localhost";
    item *I;
    int ret = 0;

    if ((I = stringmap_find(config, "auth-mysql-username"))) username = (char*)I->v;
    else {
        log_print(LOG_ERR, _("auth_mysql_init: no auth-mysql-username directive in config"));
        goto fail;
    }

    if ((I = stringmap_find(config, "auth-mysql-password"))) password = (char*)I->v;
    else {
        log_print(LOG_WARNING, _("auth_mysql_init: no auth-mysql-password directive in config; using blank password"));
        password = "";
    }

    if ((I = stringmap_find(config, "auth-mysql-database"))) database = (char*)I->v;
    else {
        log_print(LOG_ERR, _("auth_mysql_init: no auth-mysql-database directive in config"));
        goto fail;
    }

    if ((I = stringmap_find(config, "auth-mysql-hostname"))) hostname = (char*)I->v;
    else hostname = localhost;

    if ((I = stringmap_find(config, "auth-mysql-pass-query"))) user_pass_query_template = (char*)I->v;
    if ((I = stringmap_find(config, "auth-mysql-apop-query"))) apop_query_template = (char*)I->v;

    mysql = mysql_init(NULL);
    if (!mysql) {
        log_print(LOG_ERR, _("auth_mysql_init: mysql_init: failed"));
        goto fail;
    }

    if (mysql_real_connect(mysql, hostname, username, password, database, 0, NULL, 0) != mysql) {
        log_print(LOG_ERR, "auth_mysql_init: mysql_real_connect: %s", mysql_error(mysql));
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

extern int verbose; /* in main.c */

/* auth_mysql_new_apop:
 * Attempt to authenticate a user via APOP, using the template SELECT query in
 * the config file or the default defined above otherwise. */
authcontext auth_mysql_new_apop(const char *name, const char *timestamp, const unsigned char *digest, const char *host /* unused */) {
    char *query = NULL;
    authcontext a = NULL;
    char *local_part = NULL;
    const char *domain;
    item *I;
    int use_gid = 0;
    gid_t gid;

    if (!mysql) return NULL;

    /* Obtain gid to use */
    if ((I = stringmap_find(config, "auth-mysql-mail-group"))) {
        if (!parse_gid((char*)I->v, &gid)) {
            log_print(LOG_ERR, _("auth_mysql_new_apop: auth-mysql-mail-group directive `%s' does not make sense"), (char*)I->v);
            return NULL;
        }
        use_gid = 1;
    }

    domain = name + strcspn(name, "@%!");
    if (domain == name || !*domain) return NULL;
    ++domain;
    
    local_part = xmalloc(domain - name);
    if (!local_part) return NULL;
    memset(local_part, 0, domain - name);
    strncpy(local_part, name, domain - name - 1);
    
    if (mysql_ping(mysql) == -1) {
        log_print(LOG_ERR, "auth_mysql_new_apop: mysql_ping: %s", mysql_error(mysql));
        return NULL;
    }

    /* Obtain the actual query to use. */
    query = substitute_query_params(apop_query_template, local_part, domain);
    if (!query) goto fail;

    if (verbose)
        log_print(LOG_DEBUG, "auth_mysql_new_apop: SQL query: %s", query);

    if (mysql_query(mysql, query) == 0) {
        MYSQL_RES *result = mysql_store_result(mysql);
        int i;

        if (!result) {
            log_print(LOG_ERR, "auth_mysql_new_apop: mysql_store_result: %s", mysql_error(mysql));
            goto fail;
        }

        if (mysql_field_count(mysql) != 4) {
            log_print(LOG_ERR, "auth_mysql_new_apop: %d fields returned by query, should be 4: mailbox location, password hash, unix user, mailbox type", mysql_field_count(mysql));
            goto fail;
        }

        switch (i = mysql_num_rows(result)) {
        case 0:
            break;
        case 1: {
                MYSQL_ROW row = mysql_fetch_row(result);
                unsigned long *lengths;
                struct passwd *pw;
                unsigned char this_digest[16];
                MD5_CTX ctx;
                uid_t uid;

                /* These are "can't happen" errors */
                if (!row || !(lengths = mysql_fetch_lengths(result))) break;

                /* Verify that this user has a plaintext password. */
                if (strncmp(row[1], "{plaintext}", 11) != 0) {
                    log_print(LOG_WARNING, _("auth_mysql_new_apop: attempted APOP login by %s@%s, who does not have a plaintext password"), local_part, domain);
                    break;
                }
                
                /* Calculate our idea of the digest */
                MD5Init(&ctx);
                MD5Update(&ctx, (unsigned char*)timestamp, strlen(timestamp));
                MD5Update(&ctx, (unsigned char*)row[1] + 11, lengths[1] - 11);
                MD5Final(this_digest, &ctx);

                /* User was lying */
                if (memcmp(this_digest, digest, 16)) {
                    log_print(LOG_WARNING, _("auth_mysql_new_apop: failed login for %s@%s"), local_part, domain);
                    break;
                }

                /* User was not lying (about her password) */
                if (!parse_uid((const char*)row[2], &uid)) {
                    log_print(LOG_ERR, _("auth_mysql_new_apop: unix user `%s' for %s@%s does not make sense"), row[3], local_part, domain);
                    break;
                }

                pw = getpwuid(uid);

                if (!pw) {
                    log_print(LOG_ERR, "auth_mysql_new_apop: getpwuid(%d): %m", (int)uid);
                    break;
                }

                a = authcontext_new(pw->pw_uid, use_gid ? gid : pw->pw_gid,
                                    row[3], row[0], pw->pw_dir, domain);

                break;
            }

        default:
            log_print(LOG_ERR, _("auth_mysql_new_apop: database inconsistency: query for %s returned %d rows"), name, i);
            break;
        }

        mysql_free_result(result);
        
    } else {
        log_print(LOG_ERR, "auth_mysql_new_apop: mysql_query: %s", mysql_error(mysql));
    }

fail:
    if (local_part) xfree(local_part);
    if (query) xfree(query);

    return a;
}

/* auth_mysql_new_user_pass:
 * Attempt to authenticate a user via USER/PASS, using the template SELECT
 * query in the config file or the default defined above otherwise. */
authcontext auth_mysql_new_user_pass(const char *user, const char *pass, const char *host /* unused */) {
    char *query = NULL;
    authcontext a = NULL;
    char *local_part = NULL;
    const char *domain;
    item *I;
    int use_gid = 0;
    gid_t gid;

    if (!mysql) return NULL;

    /* Obtain gid to use */
    if ((I = stringmap_find(config, "auth-mysql-mail-group"))) {
        if (!parse_gid((char*)I->v, &gid)) {
            log_print(LOG_ERR, _("auth_mysql_new_apop: auth-mysql-mail-group directive `%s' does not make sense"), (char*)I->v);
            return NULL;
        }
        use_gid = 1;
    }

    domain = user + strcspn(user, "@%!");
    if (domain == user || !*domain) return NULL;
    ++domain;
    
    local_part = xmalloc(domain - user);
    if (!local_part) return NULL;
    memset(local_part, 0, domain - user);
    strncpy(local_part, user, domain - user - 1);
    
    if (mysql_ping(mysql) == -1) {
        log_print(LOG_ERR, "auth_mysql_new_user_pass: mysql_ping: %s", mysql_error(mysql));
        return NULL;
    }

    /* Obtain the actual query to use. */
    query = substitute_query_params(user_pass_query_template, local_part, domain);
    if (!query) goto fail;

    if (verbose)
        log_print(LOG_DEBUG, "auth_mysql_new_user_pass: SQL query: %s", query);

    if (mysql_query(mysql, query) == 0) {
        MYSQL_RES *result = mysql_store_result(mysql);
        int i;

        if (!result) {
            log_print(LOG_ERR, "auth_mysql_new_user_pass: mysql_store_result: %s", mysql_error(mysql));
            goto fail;
        }

        if (mysql_field_count(mysql) != 4) {
            log_print(LOG_ERR, "auth_mysql_new_user_pass: %d fields returned by query, should be 4: mailbox location, password hash, unix user, mailbox type", mysql_field_count(mysql));
            goto fail;
        }

        switch (i = mysql_num_rows(result)) {
        case 0:
            break;
        case 1: {
                MYSQL_ROW row = mysql_fetch_row(result);
                unsigned long *lengths;
                char *pwhash;
                struct passwd *pw;
                int authok = 0;
                uid_t uid;

                /* These are "can't happen" errors */
                if (!row || !(lengths = mysql_fetch_lengths(result))) break;

                /* Verify the password. There are several possibilities here. */
                pwhash = (char*)row[1];

                if (strncmp(pwhash, "{crypt}", 7) == 0) {
                    /* Password hashed by system crypt function. */
                    if (strcmp(crypt(pass, pwhash + 7), pwhash + 7) == 0) authok = 1;
                } else if (strncmp(pwhash, "{crypt_md5}", 11) == 0) {
                    /* Password hashed by crypt_md5. */
                    if (strcmp(crypt_md5(pass, pwhash + 11), pwhash + 11) == 0) authok = 1;
                } else if (strncmp(pwhash, "{plaintext}", 11) == 0) {
                    /* Plain text password, as used for APOP. */
                    if (strcmp(pass, pwhash + 11) == 0) authok = 1;
                } else if (strncmp(pwhash, "{mysql}", 7) == 0) {
                    /* MySQL PASSWORD() type password hash. */
                    char hash[17] = {0};
                    int n;
                    mysql_make_scrambled_password(hash, pass);
                    /* The MySQL password format changed, and we should accept
                     * either a 16- or 8-character long hash. */
                    switch (n = strlen(pwhash + 7)) {
                        case 8:
                            if (strncmp(pwhash + 7, hash, 8) == 0) authok = 1;
                            break;

                        case 16:
                            if (strcmp(pwhash + 7, hash) == 0) authok = 1;
                            break;

                        default:
                            log_print(LOG_ERR, _("auth_mysql_new_user_pass: %s@%s has password type mysql, but hash is of incorrect length %d"), local_part, domain, n);
                            break;
                    }
                } else if (strncmp(pwhash, "{md5}", 4) == 0 || *pwhash != '{') {
                    /* Straight MD5 password. But this might be either in hex
                     * or base64 encoding. */
                    if (*pwhash == '{')
                        pwhash += 4;

                    if (strlen(pwhash) == 32) {
                        /* Hex. */
                        if (strcasecmp(pwhash, md5_digest_str(pass, strlen(pass), 0)))
                            authok = 1;
                    } else if (strlen(pwhash) == 24) {
                        /* Base 64. */
                        if (strcmp(pwhash, md5_digest_str(pass, strlen(pass), 1)))
                            authok = 1;
                    } else
                        /* Doesn't make sense. */
                        log_print(LOG_ERR, _("auth_mysql_new_user_pass: %s@%s has password type md5, but hash is of incorrect length"), local_part, domain);
                } else {
                    /* Unknown format. */
                    log_print(LOG_ERR, _("auth_mysql_new_user_pass: %s@%s has unknown password format `%.*s'"), local_part, domain, 2 + strcspn(pwhash + 1, "}"), pwhash);
                    break;
                }

                if (!authok) {
                    log_print(LOG_ERR, _("auth_mysql_new_user_pass: %s@%s failed login with wrong password"), local_part, domain);
                    break;
                }

                if (!parse_uid((const char*)row[2], &uid)) {
                    log_print(LOG_ERR, _("auth_mysql_new_user_pass: unix user `%s' for %s@%s does not make sense"), row[3], local_part, domain);
                    break;
                }

                pw = getpwuid(uid);

                if (!pw) {
                    log_print(LOG_ERR, "auth_mysql_new_user_pass: getpwuid(%d): %m", (int)uid);
                    break;
                }

                a = authcontext_new(pw->pw_uid, use_gid ? gid : pw->pw_gid,
                                    row[3], row[0], pw->pw_dir, domain);
                break;
            }

        default:
            log_print(LOG_ERR, _("auth_mysql_new_user_pass: database inconsistency: query for %s@%s returned %d rows"), local_part, domain, i);
            break;
        }

        mysql_free_result(result);
    } else {
        log_print(LOG_ERR, "auth_mysql_new_user_pass: mysql_query: %s", mysql_error(mysql));
    }

fail:
    if (local_part) xfree(local_part);
    if (query) xfree(query);

    return a;
}

/* auth_mysql_postfork:
 * Post-fork cleanup. */
void auth_mysql_postfork() {
    mysql = NULL; /* XXX */
}

/* auth_mysql_close:
 * Close the database connection. */
void auth_mysql_close() {
    if (mysql) mysql_close(mysql);
}

/* substitute_query_params
 * Given a query template, a localpart and a domain, return a copy of the
 * template with the fields filled in. */
static char *substitute_query_params(const char *template, const char *local_part, const char *domain) {
    char *query, *l, *d;
    struct sverr err;

    /* Form escaped copies of the user and domain. */
    if (!(l = xmalloc(strlen(local_part) * 2 + 1)))
	return NULL;
    mysql_escape_string(l, local_part, strlen(local_part));

    if (!(d = xmalloc(strlen(domain) * 2 + 1))) {
	xfree(l);
	return NULL;
    }
    mysql_escape_string(d, domain, strlen(domain));

    /* Do the substitution. */
    query = substitute_variables(template, &err, 2, "local_part", l, "domain", d);
    if (!query)
        log_print(LOG_ERR, _("substitute_query_params: %s near `%.16s'"), err.msg, template + err.offset);
    
    xfree(l);
    xfree(d);
    return query;
}

#endif /* AUTH_MYSQL */
