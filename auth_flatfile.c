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
#include "config.h"
#include "util.h"

static gid_t virtual_gid;
static uid_t virtual_uid;
static char *user_passwd_file_template;

/* auth_flatfile_init:
 * Initialise the driver. Reads the config directives. */
int auth_flatfile_init() {
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

/* auth_flatfile_new_user_pass:
 * Attempt to authenticate user and pass using an alternate passwd file,
 * as configured at compile-time. This is a virtual-domains authenticator. */
authcontext auth_flatfile_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost /* unused */, const char *serverhost /* unused */) {
    FILE *fd = NULL;
    char *user_passwd = NULL, *passwd_file = NULL, *who;
    struct passwd *pwent = NULL;
    authcontext a = NULL;
    struct sverr err;

    who = username_string(user, local_part, domain);

    /* Authenticate virtual user without local_part is a hard job :) */
    if (!local_part)
        goto fail;

    /* Get password file location for this virtual domain */
    if (!(passwd_file = substitute_variables(user_passwd_file_template, &err, 1, "domain", domain))) {
        log_print(LOG_ERR, _("auth_flatfile_new_user_pass: %s near `%.16s'"), err.msg, user_passwd_file_template + err.offset);
        goto fail;
    }

    /* Try to open the password file */
    if ((fd = fopen(passwd_file, "r")) == (FILE *) NULL) {
        log_print(LOG_ERR, _("auth_flatfile_new_user_pass: unable to open virtual password file %s"), passwd_file);
        goto fail;
    }

    /* Now we look for the user password */
    pwent = fgetpwent(fd);
    while (pwent) {
        if (!strcmp(local_part, pwent->pw_name)) {
            user_passwd = xstrdup(pwent->pw_passwd);
            pwent = NULL;
            break;
        }
        pwent = fgetpwent(fd);
    }

    /* Now we need to authenticate the user */
    if (user_passwd) {
        if (!strcmp(crypt(pass, user_passwd), user_passwd))
            a = authcontext_new(virtual_uid, virtual_gid, NULL, NULL, NULL);
        else
            log_print(LOG_ERR, _("auth_flatfile_new_user_pass: failed login for %s"), who);
    }

fail:
    if (fd) fclose(fd);
    if (user_passwd) xfree(user_passwd);
    if (passwd_file) xfree(passwd_file);
    return a;
}

#endif /* AUTH_FLATFILE */
