/*
 * authswitch.c: authentication driver switch
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.5  2000/10/18 21:34:12  chris
 * Changes due to Mark Longair.
 *
 * Revision 1.4  2000/10/07 17:41:16  chris
 * Minor changes.
 *
 * Revision 1.3  2000/10/02 18:20:19  chris
 * Added session logging.
 *
 * Revision 1.2  2000/09/26 22:23:36  chris
 * Various changes.
 *
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

static const char rcsid[] = "$Id$";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <unistd.h>
#include <sys/types.h>

#include "auth_mysql.h"
#include "auth_pam.h"
/*#include "auth_passwd.h" */
#include "authswitch.h"
#include "stringmap.h"

/* auth_drivers:
 * References the various authentication drivers. New ones should be added as
 * below.
 */
struct authdrv auth_drivers[] = {
        /* This is the PAM driver, which should be used wherever possible. */
        {NULL, NULL, auth_pam_new_user_pass, NULL,
            "pam",
            "Uses Pluggable Authentication Modules"},

        /* This is an example of how to write an authentication driver, and
         * shouldn't be used on modern systems.
         */
/*      
        {auth_passwd_init, NULL, auth_passwd_new_user_pass, auth_passwd_clode,
            "passwd",
            "Uses /etc/passwd"},
*/
            
        /* This is for vmail-sql and similar schemes */
        {auth_mysql_init, auth_mysql_new_apop, auth_mysql_new_user_pass, auth_mysql_close,
            "mysql",
            "Uses a MySQL database"},
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
        char *s = (char*)malloc(13 + strlen(aa->name));
        item *I;
        sprintf(s, "auth-%s-enable", aa->name);
        I = stringmap_find(config, s);
        if (I && (!strcmp(I->v, "yes") || !strcmp(I->v, "true"))) {
            if (aa->auth_init && !aa->auth_init())
                syslog(LOG_ERR, "failed to initialise %s authentication driver", aa->name);
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
            syslog(LOG_INFO, "authcontext_new_apop: began session for `%s' with %s; uid %d, gid %d", a->credential, a->auth, getuid(), getgid());
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
        if (aar && aa->auth_new_user_pass && (a = aa->auth_new_user_pass(user, pass))) {
            a->auth = strdup(aa->name);
            a->credential = strdup(user);
            syslog(LOG_INFO, "authcontext_new_apop: began session for `%s' with %s; uid %d, gid %d", a->credential, a->auth, a->uid, a->gid);
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
        syslog(LOG_INFO, "authcontext_delete: finished session for `%s' with %s", a->credential, a->auth);

    if (a->auth) free(a->auth);
    if (a->credential) free(a->credential);
    
    free(a);
}
