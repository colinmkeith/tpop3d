/*
 * authswitch.c:
 * authentication driver switch
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <unistd.h>
#include <sys/types.h>

#ifdef AUTH_MYSQL
#include "auth_mysql.h"
#endif /* AUTH_MYSQL */

#ifdef AUTH_PAM
#include "auth_pam.h"
#endif /* AUTH_PAM */

#ifdef AUTH_PASSWD
#include "auth_passwd.h"
#endif /* AUTH_PASSWD */

#include "authswitch.h"
#include "stringmap.h"
#include "util.h"

/* auth_drivers:
 * References the various authentication drivers. New ones should be added as
 * below.
 */
struct authdrv auth_drivers[] = {
#ifdef AUTH_PAM
        /* This is the PAM driver, which should be used wherever possible. */
        {NULL, NULL, auth_pam_new_user_pass, NULL,
            "pam",
            "Uses Pluggable Authentication Modules"},
#endif /* AUTH_PAM */
            
#ifdef AUTH_PASSWD
        /* This is the old-style unix authentication driver. */
        {NULL, NULL, auth_passwd_new_user_pass, NULL,
            "passwd",
            "Uses /etc/passwd or /etc/shadow"},
#endif /* AUTH_PASSWD */
            
#ifdef AUTH_MYSQL
        /* This is for vmail-sql and similar schemes */
        {auth_mysql_init, auth_mysql_new_apop, auth_mysql_new_user_pass, auth_mysql_close,
            "mysql",
            "Uses a MySQL database"},
#endif /* AUTH_MYSQL */
    };

int *auth_drivers_running;
    
#define NUM_AUTH_DRIVERS    (sizeof(auth_drivers) / sizeof(struct authdrv))
#define auth_drivers_end    auth_drivers + NUM_AUTH_DRIVERS

/* authswitch_init:
 * Attempt to initialise all the authentication drivers listed in
 * auth_drivers. Returns the number of drivers successfully started.
 */
extern stringmap config;
    
int authswitch_init() {
    const struct authdrv *aa;
    int *aar;
    int ret = 0;

    auth_drivers_running = (int*)malloc(NUM_AUTH_DRIVERS * sizeof(int));
    memset(auth_drivers_running, 0, NUM_AUTH_DRIVERS * sizeof(int));

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar) {
        size_t l;
        char *s = (char*)malloc(l = (13 + strlen(aa->name)));
        item *I;
        snprintf(s, l, "auth-%s-enable", aa->name);
        I = stringmap_find(config, s);
        if (I && (!strcmp(I->v, "yes") || !strcmp(I->v, "true"))) {
            if (aa->auth_init && !aa->auth_init())
                print_log(LOG_ERR, "failed to initialise %s authentication driver", aa->name);
            else {
                *aar = 1;
                ++ret;
            }
        }
        free(s);
    }

    return ret;
}

/* authcontext_new_apop:
 * Attempts to authenticate the apop data with each driver in turn.
 */
authcontext authcontext_new_apop(const char *timestamp, const char *name, unsigned char *digest) {
    authcontext a = NULL;
    const struct authdrv *aa;
    int *aar;
    
    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_new_apop && (a = aa->auth_new_apop(timestamp, name, digest))) {
            a->auth = strdup(aa->name);
            a->credential = strdup(name);
            print_log(LOG_INFO, "authcontext_new_apop: began session for `%s' with %s; uid %d, gid %d", a->credential, a->auth, getuid(), getgid());
            return a;
        }

    return NULL;
}

/* authcontext_new_user_pass:
 * Attempts to authenticate user and pass with each driver in turn.
 */
authcontext authcontext_new_user_pass(const char *user, const char *pass) {
    authcontext a = NULL;
    const struct authdrv *aa;
    int *aar;

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_new_user_pass && (a = aa->auth_new_user_pass(user, pass))) {
            a->auth = strdup(aa->name);
            a->credential = strdup(user);
            print_log(LOG_INFO, "authcontext_new_user_pass: began session for `%s' with %s; uid %d, gid %d", a->credential, a->auth, a->uid, a->gid);
            return a;
        }

    return NULL;
}

/* authswitch_close:
 * Closes down each authentication driver. Note that it doesn't check whether
 * the driver started successfully, so even drivers which didn't start will
 * get called. So sue me.
 */
void authswitch_close() {
    const struct authdrv *aa;
    int *aar;

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_close) aa->auth_close();

    free(auth_drivers_running);
}

/* authcontext_new:
 * Fill in a new authentication context structure with the given information.
 */
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

    a->auth = NULL;
    a->credential = NULL;

    return a;
}

/* authcontext_delete:
 * Free data associated with an authentication context.
 */
void authcontext_delete(authcontext a) {
    if (!a) return;

    if (a->mailspool) free(a->mailspool);

    /* Only log if this is the end of the session, not the parent freeing its
     * copy of the data. (This is a hack, and I am ashamed.)
     */
    if (getuid() == a->uid && a->auth && a->credential)
        print_log(LOG_INFO, "authcontext_delete: finished session for `%s' with %s", a->credential, a->auth);

    if (a->auth) free(a->auth);
    if (a->credential) free(a->credential);
    
    free(a);
}
