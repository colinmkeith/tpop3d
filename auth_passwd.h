/*
 * auth_passwd.h:
 * authenticate using /etc/passwd or /etc/shadow
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __AUTH_PASSWD_H_ /* include guard */
#define __AUTH_PASSWD_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_PASSWD

#include "authswitch.h"

/* auth_passwd.c */
authcontext auth_passwd_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *host);

#endif /* AUTH_PASSWD */

#endif /* __AUTH_PASSWD_H_ */
