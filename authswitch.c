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
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <unistd.h>
#include <sys/types.h>

#ifdef AUTH_MYSQL
#include "auth_mysql.h"
#endif /* AUTH_MYSQL */

#ifdef AUTH_OTHER
#include "auth_other.h"
#endif /* AUTH_OTHER */

#ifdef AUTH_PERL
#include "auth_perl.h"
#endif /* AUTH_PERL */

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
#define _X(String) (String)

struct authdrv auth_drivers[] = {
#ifdef AUTH_PAM
        /* This is the PAM driver, which should be used wherever possible. */
        {NULL, NULL, auth_pam_new_user_pass, NULL, NULL, NULL,
            "pam",
            _X("Uses Pluggable Authentication Modules")},
#endif /* AUTH_PAM */
            
#ifdef AUTH_PASSWD
        /* This is the old-style unix authentication driver. */
        {NULL, NULL, auth_passwd_new_user_pass, NULL, NULL, NULL,
            "passwd",
            _X("Uses /etc/passwd or /etc/shadow")},
#endif /* AUTH_PASSWD */
            
#ifdef AUTH_MYSQL
        /* This is for vmail-sql and similar schemes */
        {auth_mysql_init, auth_mysql_new_apop, auth_mysql_new_user_pass, auth_mysql_onlogin, auth_mysql_postfork, auth_mysql_close,
            "mysql",
            _X("Uses a MySQL database")},
#endif /* AUTH_MYSQL */

#ifdef AUTH_OTHER
        /* This talks to an external program. */
        {auth_other_init, auth_other_new_apop, auth_other_new_user_pass, auth_other_onlogin, auth_other_postfork, auth_other_close,
            "other",
            _X("Uses an external program")},
#endif /* AUTH_OTHER */

#ifdef AUTH_PERL
        /* This calls into perl subroutines. */
        {auth_perl_init, auth_perl_new_apop, auth_perl_new_user_pass, auth_perl_onlogin, auth_perl_postfork, auth_perl_close,
            "perl",
            _X("Uses perl code")},
#endif /* AUTH_PERL */
};

int *auth_drivers_running;
    
#define NUM_AUTH_DRIVERS    (sizeof(auth_drivers) / sizeof(struct authdrv))
#define auth_drivers_end    auth_drivers + NUM_AUTH_DRIVERS

/* authswitch_describe:
 * Describe available authentication drivers.
 */
void authswitch_describe(FILE *fp) {
    const struct authdrv *aa;
    fprintf(fp, _("Available authentication drivers:\n\n"));
    for (aa = auth_drivers; aa < auth_drivers_end; ++aa)
        fprintf(fp, "  auth-%-11s %s\n", aa->name, _(aa->description));
    fprintf(fp, "\n");
}

/* authswitch_init:
 * Attempt to initialise all the authentication drivers listed in
 * auth_drivers. Returns the number of drivers successfully started.
 */
extern stringmap config;
    
int authswitch_init() {
    const struct authdrv *aa;
    int *aar;
    int ret = 0;

    auth_drivers_running = xcalloc(NUM_AUTH_DRIVERS, sizeof *auth_drivers_running);

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar) {
        size_t l;
        char *s = xmalloc(l = (13 + strlen(aa->name)));
        item *I;
        snprintf(s, l, "auth-%s-enable", aa->name);
        I = stringmap_find(config, s);
        if (I && (!strcmp(I->v, "yes") || !strcmp(I->v, "true"))) {
            if (aa->auth_init && !aa->auth_init())
                log_print(LOG_ERR, "failed to initialise %s authentication driver", aa->name);
            else {
                *aar = 1;
                ++ret;
            }
        }
        xfree(s);
    }

    return ret;
}

/* authcontext_new_apop:
 * Attempts to authenticate the apop data with each driver in turn. */
authcontext authcontext_new_apop(const char *name, const char *timestamp, const unsigned char *digest, const char *domain, const char *host) {
    authcontext a = NULL;
    const struct authdrv *aa;
    int *aar;
    
    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_new_apop && (a = aa->auth_new_apop(name, timestamp, digest, host))) {
            a->auth = strdup(aa->name);
            a->user = strdup(name);
            if (!a->domain && domain) a->domain = strdup(domain);
            log_print(LOG_INFO, _("authcontext_new_apop: began session for `%s' with %s; uid %d, gid %d"), a->user, a->auth, a->uid, a->gid);
            return a;
        }

    return NULL;
}

/* authcontext_new_user_pass:
 * Attempts to authenticate user and pass with each driver in turn. */
authcontext authcontext_new_user_pass(const char *user, const char *pass, const char *domain, const char *host) {
    authcontext a = NULL;
    const struct authdrv *aa;
    int *aar;

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_new_user_pass && (a = aa->auth_new_user_pass(user, pass, host))) {
            a->auth = strdup(aa->name);
            a->user = strdup(user);
            if (!a->domain && domain) a->domain = strdup(domain);
            log_print(LOG_INFO, _("authcontext_new_user_pass: began session for `%s' with %s; uid %d, gid %d"), a->user, a->auth, a->uid, a->gid);
            return a;
        }

    return NULL;
}

/* authswitch_onlogin:
 * Pass news of a successful login to any authentication drivers which are
 * interested in hearing about it. */
void authswitch_onlogin(const authcontext A, const char *host) {
    const struct authdrv *aa;
    int *aar;

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_onlogin)
            aa->auth_onlogin(A, host);
}

/* authswitch_postfork:
 * Do post-fork cleanup if defined by each driver. */
void authswitch_postfork() {
    const struct authdrv *aa;
    int *aar;

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_postfork) aa->auth_postfork();

}

/* authswitch_close:
 * Closes down each authentication driver. Note that it doesn't check whether
 * the driver started successfully, so even drivers which didn't start will
 * get called. So sue me. */
void authswitch_close() {
    const struct authdrv *aa;
    int *aar;

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_close) aa->auth_close();

    xfree(auth_drivers_running);
}

/* authcontext_new:
 * Fill in a new authentication context structure with the given information. */
authcontext authcontext_new(const uid_t uid, const gid_t gid, const char *mboxdrv, const char *mailbox, const char *home, const char *domain) {
    authcontext a;
    a = xcalloc(1, sizeof *a);
    if (!a) return NULL;

    a->uid = uid;
    a->gid = gid;

    if (mboxdrv) a->mboxdrv = strdup(mboxdrv);
    if (mailbox) a->mailbox = strdup(mailbox);

    a->auth = NULL;
    a->user = NULL;
    
    if (home) a->home = strdup(home);
    if (domain) a->domain = strdup(domain);

    return a;
}

/* authcontext_delete:
 * Free data associated with an authentication context. */
extern int post_fork;   /* in main.c */

void authcontext_delete(authcontext a) {
    if (!a) return;

    if (a->mboxdrv) xfree(a->mboxdrv);
    if (a->mailbox) xfree(a->mailbox);

    /* Only log if this is the end of the session, not the parent freeing its
     * copy of the data. (This is a hack, and I am ashamed.) */
    if (post_fork) log_print(LOG_INFO, _("authcontext_delete: finished session for `%s' with %s"), a->user, a->auth);

    if (a->auth) xfree(a->auth);
    if (a->user) xfree(a->user);
    if (a->domain) xfree(a->domain);
    if (a->home) xfree(a->home);
    
    xfree(a);
}


