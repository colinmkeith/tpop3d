/*
 * auth_passwd.c:
 * authenticate using /etc/passwd or /etc/shadow
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

#ifdef AUTH_PASSWD
static const char rcsid[] = "$Id$";

#include <sys/types.h>

#ifdef HAVE_CRYPT_H /* XXX */
#include <crypt.h>
#endif

#include <unistd.h>
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
#include "config.h"
#include "util.h"
#include "mailbox.h"

/* auth_passwd_new_user_pass:
 * Attempt to authenticate user and pass using /etc/passwd or /etc/shadow,
 * as configured at compile-time. This is not a virtual-domains authenticator,
 * so it only uses user. */
authcontext auth_passwd_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost /* unused */, const char *serverhost) {
    struct passwd *pw;
#ifdef AUTH_PASSWD_SHADOW
    struct spwd *spw;
#endif /* AUTH_PASSWD_SHADOW */
    char *user_passwd;
    char *s;
    int use_gid = 0;
    gid_t gid = 99;
    authcontext a = NULL;

    /* Check the this isn't a virtual-domain user. */
    if (local_part) return NULL;

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
    if ((s = config_get_string("auth-passwd-mail-group"))) {
        if (!parse_gid(s, &gid)) {
            log_print(LOG_ERR, _("auth_passwd_new_user_pass: auth-passwd-mail-group directive `%s' does not make sense"), s);
            return NULL;
        }
        use_gid = 1;
    }

    /* Now we need to authenticate the user; we will leave finding the
     * mailspool for later. */
    if (!strcmp(crypt(pass, user_passwd), user_passwd)) {
        a = authcontext_new(pw->pw_uid, use_gid ? gid : pw->pw_gid, NULL, NULL, pw->pw_dir);
    }
    
    return a;
}

#endif /* AUTH_PASSWD */
