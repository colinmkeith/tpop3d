/*
 * auth_pam.h: authenticate using Pluggable Authentication Modules
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

#ifndef __AUTH_PAM_H_ /* include guard */
#define __AUTH_PAM_H_

#include "authswitch.h"

#define AUTH_PAM_MAILSPOOL_DIR  "/var/spool/mail"
#undef  AUTH_PAM_MAIL_GID

#define AUTH_PAM_FACILITY       "tpop3d"

int         auth_pam_init(void);
authcontext auth_pam_new_user_pass(const char *user, const char *pass);
void        auth_pam_close(void);

#endif /* __AUTH_PAM_H_ */
