/*
 * auth_pam.c: authenticate using Pluggable Authentication Modules
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.4  2000/10/10 00:13:38  chris
 * Added more useful logging.
 *
 * Revision 1.3  2000/10/02 18:20:19  chris
 * Added config file support.
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

#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <security/pam_appl.h>

#include <sys/types.h>

#include "auth_pam.h"
#include "authswitch.h"
#include "stringmap.h"

int auth_pam_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    const struct pam_message **m;
    struct pam_response *r;

    if (!num_msg || !msg || !appdata_ptr) return PAM_CONV_ERR;
    
    *resp = (struct pam_response*)calloc(num_msg, sizeof(struct pam_response));
    if (!*resp) return PAM_CONV_ERR;

    /* Assume that any prompt is asking for a password */
    for (m = msg, r = *resp; m < msg + num_msg; ++m, ++r) {
        if ((*m)->msg_style == PAM_PROMPT_ECHO_OFF) {
            r->resp = strdup((char*)appdata_ptr);
            r->resp_retcode = 0;
        }
    }

    return PAM_SUCCESS;
}

/* auth_pam_new_user_pass:
 * Attempt to authenticate user and pass using PAM.
 */
extern stringmap config;

authcontext auth_pam_new_user_pass(const char *user, const char *pass) {
    pam_handle_t *pamh = NULL;
    struct passwd pw, *pw2;
    int r, n = PAM_SUCCESS;
    authcontext a = NULL;
    struct pam_conv conv;
    char *facility, *mailspool_dir;
    item *I;
    int use_gid = 0;
    gid_t gid;

    pw2 = getpwnam(user);
    if (!pw2) {
        syslog(LOG_ERR, "auth_pam_new_user_pass: getpwnam(%s): unknown user (%m)", user);
        return NULL;
    }
    else memcpy(&pw, pw2, sizeof(pw));

    /* Obtain facility name. */
    I = stringmap_find(config, "auth-pam-facility");
    if (I) facility = (char*)I->v;
    else facility = AUTH_PAM_FACILITY;

    /* Obtain mailspool directory */
    if ((I = stringmap_find(config, "auth-pam-mailspool-dir"))) mailspool_dir = (char*)I->v;
#ifdef AUTH_PAM_MAILSPOOL_DIR
    else mailspool_dir = AUTH_PAM_MAILSPOOL_DIR;
#else
    else {
        syslog(LOG_ERR, "auth_pam_new_user_pass: no mailspool directory known about\n");
        return NULL;
    }
#endif
 
    /* Obtain gid to use */
    if ((I = stringmap_find(config, "auth-pam-mail-group"))) {
        gid = atoi((char*)I->v);
        if (!gid) {
            struct group *grp;
            grp = getgrnam((char*)I->v);
            if (!grp) {
                syslog(LOG_ERR, "auth_pam_new_user_pass: auth-pam-mail-group directive `%s' does not make sense", I->v);
                return NULL;
            }
            gid = grp->gr_gid;
        }
        use_gid = 1;
    }
#ifdef AUTH_PAM_MAIL_GID
    else {
        gid = AUTH_PAM_MAIL_GID;
        use_gid = 1;
    }
#endif

    conv.conv = auth_pam_conversation;
    conv.appdata_ptr = (void*)pass;
    
    r = pam_start(facility, user, &conv, &pamh);

    if (r != PAM_SUCCESS) {
        syslog(LOG_ERR, "auth_pam_new_user_pass: pam_start: %s", pam_strerror(pamh, r));
        return NULL;
    }

    r = pam_authenticate(pamh, 0);

    if (r == PAM_SUCCESS) {
        char *s;
        s = (char*)malloc(strlen(mailspool_dir) + 1 + strlen(user) + 1);
        if (s) {
            sprintf(s, "%s/%s", mailspool_dir, user);
            a = authcontext_new(pw.pw_uid,
                                use_gid ? gid : pw.pw_gid,
                                s);
            free(s);
        }
    } else syslog(LOG_ERR, "auth_pam_new_user_pass: pam_authenticate(%s): %s", user, pam_strerror(pamh, r));


    r = pam_end(pamh, n);

    if (r != PAM_SUCCESS) syslog(LOG_ERR, "auth_pam_new_user_pass: pam_end: %s", pam_strerror(pamh, r));

    return a;
}
