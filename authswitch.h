/*
 * authswitch.h:
 * authentication drivers
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __AUTHSWITCH_H_ /* include guard */
#define __AUTHSWITCH_H_

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include "mailbox.h"

typedef struct _authcontext {
    uid_t uid;
    gid_t gid;
    char *mboxdrv, *mailbox;    /* Name of mailbox driver and mailbox. */
    
    char *auth;                 /* Name of authentication driver, eg `pam'.                      */
    char *user, *domain, *home; /* Name of user, associated domain, and their home directory.    */
} *authcontext;

struct authdrv {
    /* Initialise this authentication driver. Returns 1 on success or 0 on
     * failure. */
    int         (*auth_init)(void);
    
    /* Attempt to build authcontext from APOP; parameters are name, original
     * timestamp, supplied digest and the client host. */
    authcontext (*auth_new_apop)(const char *name, const char *timestamp, const unsigned char *digest, const char *host);
    
    /* Attempt to build authcontext from USER and PASS; parameters are name,
     * password and the client host. */
    authcontext (*auth_new_user_pass)(const char *user, const char *password, const char *host);

    /* Function to call after any successful authentication. */
    void        (*auth_onlogin)(const authcontext A, const char *clienthost);

    /* Clear up any resources associated with this driver prior to a fork. */
    void        (*auth_postfork)(void);

    /* Shut down this authentication driver, and free associated resources. */
    void        (*auth_close)(void);

    /* Name of the authentication driver (should be one word). */
    char *name;

    /* Description of the authentication driver. */
    char *description;
};

void authswitch_describe(FILE *fp);

int authswitch_init(void);
authcontext authcontext_new_apop(const char *name, const char *timestamp, const unsigned char *digest, const char *domain, const char *host);
authcontext authcontext_new_user_pass(const char *user, const char *pass, const char *domain, const char *host);

void authswitch_onlogin(const authcontext A, const char *host);
void authswitch_postfork(void);
void authswitch_close(void);

authcontext authcontext_new(const uid_t uid, const gid_t gid, const char *mboxdrv, const char *mailbox, const char *home, const char *domain);
void authcontext_delete(authcontext);

/* Function to find a mailbox according to the config file. */
mailbox find_mailbox(authcontext a);

#endif /* __AUTHSWITCH_H_ */
