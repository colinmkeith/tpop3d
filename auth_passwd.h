/*
 * auth_passwd.h: authenticate using /etc/passwd or /etc/shadow
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.2  2001/01/11 21:23:35  chris
 * Minor changes.
 *
 *
 */

#ifndef __AUTH_PASSWD_H_ /* include guard */
#define __AUTH_PASSWD_H_

#include "authswitch.h"

/* auth_passwd.c */
authcontext auth_passwd_new_user_pass(const char *user, const char *pass);

#endif /* __AUTH_PASSWD_H_ */
