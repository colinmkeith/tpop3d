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

#ifdef CRYPT_FUNCTION_IN_CRYPT_H    /* XXX */
#include <crypt.h>
#else
#include <unistd.h>
#endif

#include <grp.h>
#include <pwd.h>
#ifdef AUTH_PASSWD_SHADOW
#include <shadow.h>
#endif /* AUTH_PASSWD_SHADOW */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>    /* for struct stat */
#include <sys/stat.h>
     
#include "auth_passwd.h"
#include "authswitch.h"
#include "stringmap.h"
#include "util.h"
#include "mailbox.h"

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
    char *user_passwd;
    item *I;
    int use_gid = 0;
    gid_t gid = 99;
    authcontext a = NULL;

    pw = getpwnam(user);
    if (!pw) return NULL;
#ifdef AUTH_PASSWD_SHADOW
    spw = getspnam(user);
    if (!spw) return NULL;
    user_passwd = spw->sp_pwdp;
#else
    user_passwd = pw->pw_passwd;
#endif /* AUTH_PASSWD_SHADOW */

    /* Obtain gid to use */
    if ((I = stringmap_find(config, "auth-passwd-mail-group"))) {
        if (!parse_gid((char*)I->v, &gid)) {
            print_log(LOG_ERR, _("auth_passwd_new_user_pass: auth-passwd-mail-group directive `%s' does not make sense"), (char*)I->v);
            return NULL;
        }
        use_gid = 1;
    }

    /* Now we need to authenticate the user; we will leave finding the
     * mailspool for later.
     */
    if (!strcmp(crypt(pass, user_passwd), user_passwd)) {
        a = authcontext_new(pw->pw_uid, use_gid ? gid : pw->pw_gid, NULL, NULL, pw->pw_dir, NULL);
    }
    
    return a;
}

#endif /* AUTH_PASSWD */
