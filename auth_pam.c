/*
 * auth_pam.c:
 * authenticate using Pluggable Authentication Modules
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_PAM
static const char rcsid[] = "$Id$";

#include <sys/types.h> /* BSD needs this here, it seems. */

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_appl.h>

#include "auth_pam.h"
#include "authswitch.h"
#include "config.h"
#include "util.h"

/* auth_pam_conversation:
 * PAM conversation function, used to transmit the password supplied by the
 * user to the PAM modules for authentication. */
int auth_pam_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    const struct pam_message **m;
    struct pam_response *r;

    if (!num_msg || !msg || !appdata_ptr) return PAM_CONV_ERR;
    
    *resp = (struct pam_response*)xcalloc(num_msg, sizeof(struct pam_response));
    if (!*resp) return PAM_CONV_ERR;

    /* Assume that any prompt is asking for a password */
    for (m = msg, r = *resp; m < msg + num_msg; ++m, ++r) {
        if ((*m)->msg_style == PAM_PROMPT_ECHO_OFF) {
            r->resp = xstrdup((char*)appdata_ptr);
            r->resp_retcode = 0;
        }
    }

    return PAM_SUCCESS;
}

/* auth_pam_do_authentication FACILITY USER PASSWORD
 * Tries to authenticate USER with PASSWORD using the named PAM FACILITY,
 * returning nonzero on success or zero on failure. */
static int auth_pam_do_authentication(const char *facility, const char *user, const char *pass, const char *clienthost) {
    struct pam_conv conv;
    pam_handle_t *pamh = NULL;
    int result = 0, r;
    
    /* This will generate a warning on Solaris; I can't see an easy fix. */
    conv.conv = auth_pam_conversation;
    conv.appdata_ptr = (void*)pass;
    
    r = pam_start(facility, user, &conv, &pamh);

    if (r != PAM_SUCCESS) {
        log_print(LOG_ERR, "auth_pam_new_user_pass: pam_start: %s", pam_strerror(pamh, r));
        return 0;
    }
    
    /* We want to be able to test against the client IP; make the remote host
     * information available to the PAM stack. */
    r = pam_set_item(pamh, PAM_RHOST, clienthost);
    
    if (r != PAM_SUCCESS) {
        log_print(LOG_ERR, "auth_pam_new_user_pass: pam_start: %s", pam_strerror(pamh, r));
        return 0;
    }

    /* Authenticate user. */
    r = pam_authenticate(pamh, 0);

    if (r == PAM_SUCCESS) {
        /* OK, is the account presently allowed to log in? */
        r = pam_acct_mgmt(pamh, PAM_SILENT);
        if (r == PAM_SUCCESS)
            /* Succeeded. */
            result = 1;
        else
            /* Failed; account is disabled or something. */
            log_print(LOG_ERR, "auth_pam_new_user_pass: pam_acct_mgmt(%s): %s", user, pam_strerror(pamh, r));
    } else
        /* User did not authenticate. */
        log_print(LOG_ERR, "auth_pam_new_user_pass: pam_authenticate(%s): %s", user, pam_strerror(pamh, r));

    r = pam_end(pamh, r);
    if (r != PAM_SUCCESS) log_print(LOG_ERR, "auth_pam_new_user_pass: pam_end: %s", pam_strerror(pamh, r));

    return result;
}

/* auth_pam_new_user_pass:
 * Attempt to authenticate user and pass using PAM. This is not a
 * virtual-domains authenticator, so it only looks at user. */
#ifdef REALLY_UGLY_PAM_HACK
pid_t auth_pam_child_pid;
#endif
authcontext auth_pam_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost) {
    struct passwd pw, *pw2;
    char *s;
    int use_gid = 0;
    gid_t gid = 99;
    static const char *facility;
    int authenticated = 0;

    /* Check the this isn't a virtual-domain user. */
    if (local_part) return NULL;

    /* It is possible to use PAM to authenticate users who do not exist as
     * system users. We support this by defining an auth-pam-mail-user
     * configuration option which is used to obtain the user information
     * for a non-system user to be authenticated against PAM. */
    if (!(pw2 = getpwnam(user))) {
        char *s;
        if ((s = config_get_string("auth-pam-mail-user"))) {
            uid_t u;
            if (parse_uid(s, &u)) {
                if (!(pw2 = getpwuid(u)))
                    log_print(LOG_ERR, _("auth_pam_new_user_pass: auth-pam-mail-user directive `%s' does not correspond to a real user"), s);
            } else
                log_print(LOG_ERR, _("auth_pam_new_user_pass: auth-pam-mail-user directive `%s' does not make sense"), s);
        }

        if (!pw2)
            return NULL;
    }

    /* Copy the password structure, since it is in static storage and may
     * get overwritten by calls in the PAM code. */
    pw = *pw2;

    /* pw now contains either the data for the real UNIX user named or the UNIX
     * user given by the auth-pam-mail-user config option. */

    /* Obtain facility name. */
    if (!facility && !(facility = config_get_string("auth-pam-facility")))
        facility = AUTH_PAM_FACILITY;

    /* Obtain gid to use */
    if ((s = config_get_string("auth-pam-mail-group"))) {
        if (!parse_gid(s, &gid)) {
            log_print(LOG_ERR, _("auth_pam_new_user_pass: auth-pam-mail-group directive `%s' does not make sense"), s);
            return NULL;
        }
        use_gid = 1;
    }

    /* 
     * On many systems, PAM leaks memory, which is a problem for a daemon like
     * tpop3d which does all authentication in the main daemon. So we
     * optionally implement a really ugly hack where we fork a process in
     * which to interact with PAM.
     */

#ifdef REALLY_UGLY_PAM_HACK
    {
        int pfd[2];
        char res = 0;
        ssize_t n;
        
        /* 
         * The child process writes a byte zero into the pipe on failure or a
         * one on success. Don't use the exit value because we don't want to
         * have to piss about with the SIGCHLD handler.
         */
        
        if (pipe(pfd) == -1)
            log_print(LOG_ERR, "auth_pam_new_user_pass: pipe: %m");
        else {
            switch (auth_pam_child_pid = fork()) {
                case 0:
                    close(pfd[0]);
                    if (xwrite(pfd[1], auth_pam_do_authentication(facility, user, pass, clienthost) ? "\001" : "\0", 1) == -1)
                        /* This is really bad. The parent may hang waiting for us. */
                        log_print(LOG_ERR, _("auth_pam_new_user_pass: (child process): write: %m"));
                    close(pfd[1]);
                    _exit(0);

                case -1:
                    close(pfd[0]);
                    close(pfd[1]);
                    log_print(LOG_ERR, "auth_pam_new_user_pass: fork: %m");
                    break;

                default:
                    close(pfd[1]);
                    while ((n = read(pfd[0], &res, 1)) == -1 && errno == EINTR);
                    close(pfd[0]);
                    if (n <= 0) {
                        /* Bad. Read error, child probably crashed. */
                        if (n == -1)
                            log_print(LOG_ERR, "auth_pam_new_user_pass: read: %m");
                        else 
                            log_print(LOG_ERR, _("auth_pam_new_user_pass: authentication child did not send status (shouldn't happen)"));
                        authenticated = 0;
                    } else
                        /* Good. Byte returned. */
                        authenticated = res;
                    break;
            }
        }
    }
#else
    authenticated = auth_pam_do_authentication(facility, user, pass, clienthost);
#endif  /* REALLY_UGLY_PAM_HACK */
    
    if (authenticated)
        return authcontext_new(pw.pw_uid, use_gid ? gid : pw.pw_gid, NULL, NULL, pw.pw_dir);
    else
        return NULL;
}

#endif /* AUTH_PAM */
