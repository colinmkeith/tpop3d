/*
 * auth_pam.c: authenticate using Pluggable Authentication Modules
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.2  2000/09/26 22:23:36  chris
 * Various changes.
 *
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

static const char rcsid[] = "$Id$";

#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <security/pam_appl.h>

#include <sys/types.h>

#include "auth_pam.h"
#include "authswitch.h"

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
authcontext auth_pam_new_user_pass(const char *user, const char *pass) {
    pam_handle_t *pamh = NULL;
    struct passwd pw, *pw2;
    int r, n = PAM_SUCCESS;
    authcontext a = NULL;
    struct pam_conv conv;

    pw2 = getpwnam(user);
    if (!pw2) return NULL;
    else memcpy(&pw, pw2, sizeof(pw));

    conv.conv = auth_pam_conversation;
    conv.appdata_ptr = (void*)pass;
    
    r = pam_start(AUTH_PAM_FACILITY, user, &conv, &pamh);

    if (r != PAM_SUCCESS) {
        syslog(LOG_ERR, "auth_pam_new_user_pass: pam_start: %s", pam_strerror(pamh, r));
        return NULL;
    }

    r = pam_authenticate(pamh, 0);

    if (r == PAM_SUCCESS) {
        char *s;
        s = (char*)malloc(strlen(AUTH_PAM_MAILSPOOL_DIR) + 1 + strlen(user) + 1);
        if (s) {
            sprintf(s, AUTH_PAM_MAILSPOOL_DIR"/%s", user);
            a = authcontext_new(pw.pw_uid,
#ifndef AUTH_PAM_MAIL_GID
                                pw.pw_gid,
#else
                                AUTH_PAM_MAIL_GID,
#endif
                                s);
            free(s);
        }
    }

    r = pam_end(pamh, n);

    if (r != PAM_SUCCESS) syslog(LOG_ERR, "auth_pam_new_user_pass: pam_end: %s", pam_strerror(pamh, r));

    return a;
}
