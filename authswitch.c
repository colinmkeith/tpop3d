/*
 * authswitch.c:
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

static const char rcsid[] = "$Id$";

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "auth_pam.h"
#include "authswitch.h"

/* auth_drivers:
 * References the various authentication drivers. New ones should be added as
 * below, retaining the final NULL.
 */
const struct authdrv auth_drivers[] = {
        /* This is the PAM driver, which should be used wherever possible. */
        {NULL, NULL, auth_pam_new_user_pass, NULL,
            "pam",
            "Uses Pluggable Authentication Modules, with a service name of \"tpop3d\""},

        /* This is an example of how to write an authentication driver, and
         * shouldn't be used on modern systems.
         */
/*      
        {auth_passwd_init, NULL, auth_passwd_new_user_pass, auth_passwd_clode,
            "passwd",
            "Uses /etc/passwd"},
*/
            
        /* This is for vmail-sql and similar schemes */
/*
        {auth_mysql_init, auth_mysql_new_apop, auth_mysql_new_user_pass, auth_mysql_close,
            "mysql",
            "Uses a MySQL database"},
*/
        NULL
    };

/* authswitch_init:
 * Attempt to initialise all the authentication drivers listed in
 * auth_drivers.
 */
int authswitch_init() {
    const struct authdrv *aa;

    for (aa = auth_drivers; aa; ++aa)
        if (aa->auth_init && !aa->auth_init()) syslog(LOG_ERR, "failed to initialise %s authentication driver", aa->name);
}

/* authcontext_new_apop:
 * Attempts to authenticate the apop data with each driver in turn.
 */
authcontext authcontext_new_apop(const char *timestamp, const char *name, unsigned char *digest) {
    authcontext a = NULL;
    const struct authdrv *aa;

    for (aa = auth_drivers; aa; ++aa)
        if (aa->auth_new_apop && (a = aa->auth_new_apop(timestamp, name, digest))) return a;

    return NULL;
}

/* authcontext_new_user_pass:
 * Attempts to authenticate user and pass with each driver in turn.
 */
authcontext authcontext_new_user_pass(const char *user, const char *pass) {
    authcontext a = NULL;
    const struct authdrv *aa;

    for (aa = auth_drivers; aa; ++aa)
        if (aa->auth_new_user_pass && (a = aa->auth_new_user_pass(user, pass))) return a;

    return NULL;
}

/* authswitch_close:
 * Closes down each authentication driver. Note that it doesn't check whether
 * the driver started successfully, so even drivers which didn't start will
 * get called. So sue me.
 */
void authswitch_close() {
    const struct authdrv *aa;

    for (aa = auth_drivers; aa; ++aa)
        if (aa->auth_close) aa->auth_close();

}

authcontext authcontext_new(const uid_t uid, const gid_t gid, const char *mailspool) {
    authcontext a;
    a = (authcontext)malloc(sizeof(struct _authcontext));
    if (!a) return NULL;

    a->uid = uid;
    a->gid = gid;
    a->mailspool = strdup(mailspool);
    if (!a->mailspool) {
        free(a);
        return NULL;
    }

    return a;
}

void authcontext_delete(authcontext a) {
    if (!a) return;

    if (a->mailspool) free(a->mailspool);
    free(a);
}
