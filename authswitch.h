/*
 * authswitch.h: authentication drivers
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.2  2000/10/02 18:20:19  chris
 * Minor changes.
 *
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

#ifndef __AUTHSWITCH_H_ /* include guard */
#define __AUTHSWITCH_H_

#include <stdlib.h>

#include <sys/types.h>

typedef struct _authcontext {
    uid_t uid;
    gid_t gid;
    char *mailspool;
    /* Some random information which is filled in by the auth switch */
    char *auth;
    char *credential;
} *authcontext;

struct authdrv {
    /* Initialise this authentication driver. Returns 1 on success or 0 on
     * failure.
     */
    int         (*auth_init)(void);
    
    /* Attempt to build authcontext from APOP; parameters are name, original
     * timestamp, and supplied digest.
     */
    authcontext (*auth_new_apop)(const char *, const char *, const unsigned char *);
    
    /* Attempt to build authcontext from USER and PASS; parameters are name
     * and password.
     */
    authcontext (*auth_new_user_pass)(const char *, const char *);

    /* Shut down this authentication driver, and free associated resources. */
    void        (*auth_close)(void);

    /* Name of the authentication driver (should be one word). */
    char *name;

    /* Description of the authentication driver. */
    char *description;
};

void authswitch_init();
authcontext authcontext_new_apop(const char *timestamp, const char *name, unsigned char *digest);
authcontext authcontext_new_user_pass(const char *user, const char *pass);
void authswitch_close();

authcontext authcontext_new(const uid_t uid, const gid_t gid, const char *mailspool);
void authcontext_delete(authcontext);

#endif /* __AUTHSWITCH_H_ */
