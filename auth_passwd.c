/*
 * auth_passwd.c:
 * authenticate using /etc/passwd or /etc/shadow
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_PASSWD
static const char rcsid[] = "$Id$";

#include <sys/types.h>

#include <crypt.h>
#include <grp.h>
#include <pwd.h>
#ifdef AUTH_PASSWD_SHADOW
#include <shadow.h>
#endif /* AUTH_PASSWD_SHADOW */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "auth_passwd.h"
#include "authswitch.h"
#include "stringmap.h"
#include "util.h"

/* auth_passwd_new_user_pass:
 * Attempt to authenticate user and pass using /etc/passwd or /etc/shadow,
 * as configured at compile-time.
 */
extern stringmap config;

authcontext auth_passwd_new_user_pass(const char *user, const char *pass) {
    struct passwd *pw;
#ifdef AUTH_PASSWD_SHADOW
    struct spwd *spw;
#endif /* AUTH_PASSWD_SHADOW */
    char *mailspool_dir;
    item *I;
    int use_gid = 0;
    gid_t gid = 99;
    authcontext a = NULL;

    pw = getpwnam(user);
    if (!pw) return NULL;
#ifdef AUTH_PASSWD_SHADOW
    spw = getspnam(user);
    if (!spw) return NULL;
#endif /* AUTH_PASSWD_SHADOW */

    if ((I = stringmap_find(config, "auth-passwd-mailspool-dir"))) mailspool_dir = (char*)I->v;
#ifdef AUTH_PASSWD_MAILSPOOL_DIR
    else mailspool_dir = AUTH_PASSWD_MAILSPOOL_DIR;
#else
    else {
        print_log(LOG_ERR, _("auth_passwd_new_user_pass: no mailspool directory known about"));
        return NULL;
    }
#endif

    /* Obtain gid to use. */
    if ((I = stringmap_find(config, "auth-passwd-mail-group"))) {
        gid = atoi((char*)I->v);
        if (!gid) {
            struct group *grp;
            grp = getgrnam((char*)I->v);
            if (!grp) {
                print_log(LOG_ERR, _("auth_passwd_new_user_pass: auth-passwd-mail-group directive `%s' does not make sense"), (char*)I->v);
                return NULL;
            }
            gid = grp->gr_gid;
        }
        use_gid = 1;
    }
#ifdef AUTH_PASSWD_MAIL_GID
    else {
        gid = AUTH_PAM_MAIL_GID;
        use_gid = 1;
    }
#endif

    /* Now we need to authenticate the user. */
#ifdef AUTH_PASSWD_SHADOW
    /* Using shadow passwords. */
    if (!strcmp(crypt(pass, spw->sp_pwdp), spw->sp_pwdp)) {
#else
    /* Using normal passwords. */
    if (!strcmp(crypt(pass, pw->pw_passwd), pw->pw_passwd)) {
#endif /* AUTH_PASSWD_SHADOW */
        /* OK, user is authenticated. */
        char *s;
        size_t l;
        s = (char*)malloc(l = (strlen(mailspool_dir) + 1 + strlen(user) + 1));

        if (s) {
            snprintf(s, l, "%s/%s", mailspool_dir, user);
            a = authcontext_new(pw->pw_uid,
                    use_gid ? gid : pw->pw_gid,
                    s);
            free(s);
        }
    }

    return a;
}

#endif /* AUTH_PASSWD */
