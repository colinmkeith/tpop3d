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

#ifdef AUTH_LDAP
#include "auth_ldap.h"
#endif /* AUTH_LDAP */

#ifdef AUTH_MYSQL
#include "auth_mysql.h"
#endif /* AUTH_MYSQL */

#ifdef AUTH_OTHER
#include "auth_other.h"
#endif /* AUTH_OTHER */

#ifdef AUTH_FLATFILE
#include "auth_flatfile.h"
#endif /* AUTH_FLATFILE */

#ifdef AUTH_PERL
#include "auth_perl.h"
#endif /* AUTH_PERL */

#ifdef AUTH_PAM
#include "auth_pam.h"
#endif /* AUTH_PAM */

#ifdef AUTH_PASSWD
#include "auth_passwd.h"
#endif /* AUTH_PASSWD */

#ifdef USE_WHOSON
#include <whoson.h>
#endif

#include "authswitch.h"
#include "config.h"
#include "stringmap.h"
#include "util.h"

/* auth_drivers:
 * References the various authentication drivers. New ones should be added as
 * below. */
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
        /* This is for vmail-sql and similar schemes. */
        {auth_mysql_init, auth_mysql_new_apop, auth_mysql_new_user_pass, auth_mysql_onlogin, auth_mysql_postfork, auth_mysql_close,
            "mysql",
            _X("Uses a MySQL database")},
#endif /* AUTH_MYSQL */

#ifdef AUTH_LDAP
        /* Authenticate against a directory. */
        {auth_ldap_init, NULL, auth_ldap_new_user_pass, NULL, auth_ldap_postfork, auth_ldap_close,
            "ldap",
            _X("Uses an LDAP directory")},
#endif /* AUTH_LDAP */
            
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

#ifdef AUTH_FLATFILE
        /* Authenticate against /etc/passwd-style flat files. */
        {auth_flatfile_init, NULL, auth_flatfile_new_user_pass, NULL, NULL, NULL,
            "flatfile",
            _X("Uses /etc/passwd-style flat files")},
#endif /* AUTH_FLATFILE */
};

int *auth_drivers_running;
    
#define NUM_AUTH_DRIVERS    (sizeof(auth_drivers) / sizeof(struct authdrv))
#define auth_drivers_end    auth_drivers + NUM_AUTH_DRIVERS

/* username_string:
 * Return a string describing the name of a user, of the form
 *   [<user>; <local-part>@<domain>] */
char *username_string(const char *user, const char *local_part, const char *domain) {
    static char *buf;
    static size_t nbuf;
    size_t l;
    if (local_part && domain) {
        if (nbuf < (l = strlen(user) + strlen(local_part) + strlen(domain) + 6))
            buf = xrealloc(buf, nbuf = l);
        sprintf(buf, "[%s; %s@%s]", user, local_part, domain);
    } else if (domain) {
        if (nbuf < (l = strlen(user) + strlen(domain) + 6))
            buf = xrealloc(buf, nbuf = l);
        sprintf(buf, "[%s; @%s]", user, domain);
    } else {
        if (nbuf < (l = strlen(user) + 3))
            buf = xrealloc(buf, nbuf = l);
        sprintf(buf, "[%s]", user);
    }
    return buf;
}


/* authswitch_describe:
 * Describe available authentication drivers. */
void authswitch_describe(FILE *fp) {
    const struct authdrv *aa;
    fprintf(fp, _("Available authentication drivers:\n\n"));
    for (aa = auth_drivers; aa < auth_drivers_end; ++aa)
        fprintf(fp, "  auth-%-11s %s\n", aa->name, _(aa->description));
    fprintf(fp, "\n");
}

/* authswitch_init:
 * Attempt to initialise all the authentication drivers listed in
 * auth_drivers. Returns the number of drivers successfully started. */
extern stringmap config;
#ifdef USE_DRAC
static char *drac_server;
#endif
#ifdef USE_WHOSON
static int whoson_enable;
#endif
    
int authswitch_init(void) {
    const struct authdrv *aa;
    int *aar;
    int ret = 0;

    auth_drivers_running = xcalloc(NUM_AUTH_DRIVERS, sizeof *auth_drivers_running);

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar) {
        size_t l;
        char *s;
        s = xmalloc(l = (13 + strlen(aa->name)));
        snprintf(s, l, "auth-%s-enable", aa->name);
        if (config_get_bool(s)) {
            if (aa->auth_init && !aa->auth_init())
                log_print(LOG_ERR, _("failed to initialise %s authentication driver"), aa->name);
            else {
                *aar = 1;
                ++ret;
            }
        }
        xfree(s);
    }

#ifdef USE_DRAC
    if ((drac_server = config_get_string("drac-server")))
        log_print(LOG_INFO, _("will notify DRAC server `%s' of logins"), drac_server);
#endif

#ifdef USE_WHOSON
    if ((whoson_enable = config_get_bool("whoson-enable")))
        log_print(LOG_INFO, _("will notify logins by WHOSON"));
#endif
    
    return ret;
}

/* authcontext_new_apop:
 * Attempts to authenticate the apop data with each driver in turn. */
authcontext authcontext_new_apop(const char *user, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost, const char *serverhost) {
    authcontext a = NULL;
    const struct authdrv *aa;
    int *aar;
    char *x = NULL;
    const char *l = NULL, *d = NULL;

    l = local_part;
    d = domain;
 
    /* If no local-part has been explicitly supplied, then we try to construct
     * one by splitting up the username over one of the characters listed in
     * DOMAIN_SEPARATORS. This is distinct from the append-domain
     * functionality, which will attempt to use the user's supplied username
     * as a local-part, with the listener domain as the domain, and the
     * strip-domain functionality, which will suppress the domain supplied by
     * the user. */
    if (!local_part && domain) {
        int n;
        n = strcspn(user, DOMAIN_SEPARATORS);
        if (n > 0 && user[n]) {
            x = xstrdup(user);
            x[n] = 0;
            l = x;
            d = l + n + 1;
        } else
            l = NULL;
    }
    
    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_new_apop && (a = aa->auth_new_apop(user, l, d, timestamp, digest, clienthost, serverhost))) {
            a->auth = xstrdup(aa->name);
            a->user = xstrdup(user);
            if (!a->local_part && l)
                a->local_part = xstrdup(l);
            if (!a->domain && d)
                a->domain = xstrdup(d);
            log_print(LOG_INFO, _("authcontext_new_apop: began session for `%s' with %s; uid %d, gid %d"), a->user, a->auth, a->uid, a->gid);
            break;
        }

    xfree(x);
    
    return a;
}

/* authcontext_new_user_pass:
 * Attempts to authenticate user and pass with each driver in turn. */
authcontext authcontext_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost) {
    authcontext a = NULL;
    const struct authdrv *aa;
    int *aar;
    char *x = NULL;
    const char *l = NULL, *d = NULL;

    /* This is here mainly for users who forgot to switch off LDAP anonymous
     * authentication.... */
    if (*pass == 0 && !config_get_bool("permit-empty-password")) {
        log_print(LOG_WARNING, _("authcontext_new_user_pass: rejecting login attempt by `%s' with empty password"), user);
        return NULL;
    }
    
    l = local_part;
    d = domain;
    
    /* Maybe split local part and domain (see above). */
    if (!local_part && domain) {
        int n;
        n = strcspn(user, DOMAIN_SEPARATORS);
        if (n > 0 && user[n]) {
            x = xstrdup(user);
            x[n] = 0;
            l = x;
            d = l + n + 1;
        } else
            l = NULL;
    }

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_new_user_pass && (a = aa->auth_new_user_pass(user, l, d, pass, clienthost, serverhost))) {
            a->auth = xstrdup(aa->name);
            a->user = xstrdup(user);
            if (!a->local_part) {
                if (l)
                    a->local_part = xstrdup(l);
                else
                    a->local_part = xstrdup(user);
            }
            if (!a->domain && d)
                a->domain = xstrdup(d);
            log_print(LOG_INFO, _("authcontext_new_user_pass: began session for `%s' with %s; uid %d, gid %d"), a->user, a->auth, a->uid, a->gid);
            break;
        }

    xfree(x);
    
    return a;
}

/* authswitch_onlogin:
 * Pass news of a successful login to any authentication drivers which are
 * interested in hearing about it. host is the IP address in dotted-quad
 * form. */
void authswitch_onlogin(const authcontext A, const char *clienthost, const char *serverhost) {
    const struct authdrv *aa;
    int *aar;
#ifdef USE_DRAC
    /* in -ldrac */
    int dracauth(char *server, unsigned long userip, char **errmsg);
#endif

#ifdef USE_WHOSON
    char buf[128] = {0};
    /* Notify whoson server the user has logged in correctly */
    if (wso_login(clienthost, A->user, buf, sizeof(buf)) == -1)
        log_print(LOG_ERR, "authswitch_onlogin: wso_login: %s", buf);
#endif /* USE_WHOSON */
    
#ifdef USE_DRAC
    /* Optionally, notify a DRAC -- dynamic relay authentication control -- 
     * server of the login. This uses some wacky RPC thing contained in
     * -ldrac. */
    if (drac_server) {
        char *errmsg;
        if (dracauth(drac_server, inet_addr(host), &errmsg))
            log_print(LOG_ERR, "authswitch_onlogin: dracauth: %s", errmsg);
    }
#endif /* USE_DRAC */

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_onlogin)
            aa->auth_onlogin(A, clienthost, serverhost);
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
 * Closes down any authentication drivers which have been started. */
void authswitch_close() {
    const struct authdrv *aa;
    int *aar;

    for (aa = auth_drivers, aar = auth_drivers_running; aa < auth_drivers_end; ++aa, ++aar)
        if (*aar && aa->auth_close) aa->auth_close();

    xfree(auth_drivers_running);
}

/* authcontext_new:
 * Fill in a new authentication context structure with the given information. */
authcontext authcontext_new(const uid_t uid, const gid_t gid, const char *mboxdrv, const char *mailbox, const char *home) {
    authcontext a;
    a = xcalloc(1, sizeof *a);

    a->uid = uid;
    a->gid = gid;

    if (mboxdrv)
        a->mboxdrv = xstrdup(mboxdrv);
    if (mailbox)
        a->mailbox = xstrdup(mailbox);

    a->auth = NULL;
    a->user = NULL;
    
    if (home)
        a->home = xstrdup(home);

    return a;
}

/* authcontext_delete:
 * Free data associated with an authentication context. */
extern int post_fork;   /* in main.c */

void authcontext_delete(authcontext a) {
    if (!a) return;

    xfree(a->mboxdrv);
    xfree(a->mailbox);
    xfree(a->auth);
    xfree(a->user);
    xfree(a->local_part);
    xfree(a->domain);
    xfree(a->home);
    
    xfree(a);
}


