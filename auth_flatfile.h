/*
 * auth_flatfile.h:
 * Authenticate users using an alternate passwd file
 *
 * designed for tpop3d by Angel Marin <anmar@gmx.net> 
 * Copyright (c) 2002 Angel Marin, Chris Lightfoot. All rights reserved.                 
 */

#ifndef __AUTH_FLATFILE_H_ /* include guard */
#define __AUTH_FLATFILE_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_FLATFILE

#include "authswitch.h"

/* auth_flatfile.c */
int auth_flatfile_init(void);
authcontext auth_flatfile_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost);
authcontext auth_flatfile_new_apop(const char *user, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost, const char *serverhost);


#endif /* AUTH_FLATFILE */

#endif /* __AUTH_FLATFILE_H_ */
