/*
 * auth_flatfile.c:
 * Authenticate users using an alternate passwd file
 *
 * designed for tpop3d by Angel Marin <anmar@gmx.net>
 * Copyright (c) 2002 Angel Marin, Chris Lightfoot. All rights reserved.
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_FLATFILE
static const char rcsid[] = "$Id$";

#include <sys/types.h>

#ifdef HAVE_CRYPT_H /* XXX */
#include <crypt.h>
#endif

#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "auth_flatfile.h"
#include "authswitch.h"
#include "password.h"
#include "config.h"
#include "util.h"

static gid_t virtual_gid;
static uid_t virtual_uid;
static char *user_passwd_file_template;

/* auth_flatfile_init:
 * Initialise the driver. Reads the config directives. */
int auth_flatfile_init(void) {
    char *s;
    int ret = 0;

    /* Obtain uid to use */
    if ((s = config_get_string("auth-flatfile-mail-user"))) {
        if (!parse_uid(s, &virtual_uid)) {
            log_print(LOG_ERR, _("auth_flatfile_init: auth-flatfile-mail-user directive `%s' does not make sense"), s);
            goto fail;
        }
    } else {
        log_print(LOG_ERR, _("auth_flatfile_init: no auth-flatfile-mail-user directive in config"));
        goto fail;
    }

    /* Obtain gid to use */
    if ((s = config_get_string("auth-flatfile-mail-group"))) {
        if (!parse_gid(s, &virtual_gid)) {
            log_print(LOG_ERR, _("auth_flatfile_init: auth-flatfile-mail-group directive `%s' does not make sense"), s);
            goto fail;
        }
    } else {
        log_print(LOG_ERR, _("auth_flatfile_init: no auth-flatfile-mail-group directive in config"));
        goto fail;
    }

    /* Obtain path template to passwd file */
    if ((s = config_get_string("auth-flatfile-passwd-file"))) {
	user_passwd_file_template = s;
    } else {
        log_print(LOG_ERR, _("auth_flatfile_init: no auth-flatfile-passwd-file directive in config"));
        goto fail;
    }

    ret = 1;

fail:
    return ret;
}

/* read_user_passwd LOCALPART DOMAIN
 * Read the password hash from the proper flat file for the given LOCALPART and
 * DOMAIN. Returns the password or NULL if not found. The files are structured
 * with colon-separated fields, where the first field is the local-part and the
 * second field to the password hash. Any subsequent fields are ignored. */
static char *read_user_passwd(const char *local_part, const char *domain) {
    FILE *fp = NULL;
    char *filename = NULL, *result = NULL;
    struct sverr err;
    static char *buf, *pwhash;
    static size_t buflen;
    size_t i, linenum;
    int c;

    if (!(filename = substitute_variables(user_passwd_file_template, &err, 1, "domain", domain))) {
        log_print(LOG_ERR, _("read_user_passwd: %s near `%.16s'"), err.msg, user_passwd_file_template + err.offset);
        goto fail;
    }

    if (!(fp = fopen(filename, "rt"))) {
        log_print(LOG_ERR, _("read_user_passwd: flat file %s: %m"), filename);
        goto fail;
    }

    /* Read lines from the file. */
    if (!buf)
        buf = xmalloc(buflen = 1024);
    
    linenum = 0;
    while (1) {
        char *user, *end;
        
        i = 0;
        while ((c = getc(fp)) != EOF) {
            if (c == '\n')
                break;
            buf[i++] = (char)c;
            if (i == buflen)
                buf = xrealloc(buf, buflen *= 2);
        }

        buf[i] = 0;

        if (c == EOF) {
            if (ferror(fp)) {
                /* Read error. */
                log_print(LOG_ERR, _("read_user_passwd: flat file %s: %m"), filename);
                goto fail;
            } else if (i == 0)
                /* Read nothing at end of file. */
                break;
        }

        /* OK, have a line. */
        user = buf;
        pwhash = strchr(buf, ':');
        if (!pwhash) {
            log_print(LOG_WARNING, _("read_user_passwd: flat file %s: line %u: bad format (missing :)"), filename, (unsigned)linenum);
            continue;
        }
        
        *pwhash++ = 0;

        /* Check username. */
        if (strcmp(user, local_part) != 0)
            continue;

        if ((end = strchr(pwhash, ':')))
            *end = 0;

        result = pwhash;

        break;
    }
    
fail:
    if (fp)
        fclose(fp);
    
    if (filename)
        xfree(filename);

    return result;
}

/* auth_flatfile_new_user_pass:
 * Attempt to authenticate user and pass using an alternate passwd file,
 * as configured at compile-time. This is a virtual-domains authenticator. */
authcontext auth_flatfile_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost /* unused */, const char *serverhost /* unused */) {
    authcontext a = NULL;
    char *pwhash, *who;

    if (!local_part) return NULL;
    
    who = username_string(user, local_part, domain);

    pwhash = read_user_passwd(local_part, domain);
    if (pwhash) {
        if (check_password(who, pwhash, pass, "{crypt}"))
            a = authcontext_new(virtual_uid, virtual_gid, NULL, NULL, NULL);
        else
            log_print(LOG_ERR, _("auth_flatfile_new_user_pass: failed login for %s"), who);
    }

    return a;
}

/* auth_flatfile_new_apop:
 * Attempt to authenticate user via APOP using an alternate passwd file,
 * as configured at compile-time. This is a virtual-domains authenticator. */
authcontext auth_flatfile_new_apop(const char *user, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost /* unused */, const char *serverhost /* unused */) {
    authcontext a = NULL;
    char *pwhash, *who;

    if (!local_part) return NULL;

    who = username_string(user, local_part, domain);

    pwhash = read_user_passwd(local_part, domain);
    if (pwhash) {
        if (check_password_apop(who, pwhash, timestamp, digest))
            a = authcontext_new(virtual_uid, virtual_gid, NULL, NULL, NULL);
        else
            log_print(LOG_ERR, _("auth_flatfile_new_apop: failed login for %s"), who);
    }

    return a;
}


#endif /* AUTH_FLATFILE */
