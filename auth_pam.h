/*
 * auth_pam.h:
 * authenticate using Pluggable Authentication Modules
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __AUTH_PAM_H_ /* include guard */
#define __AUTH_PAM_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_PAM

#include "authswitch.h"

/* config directive auth-pam-mailspool-dir */
#define AUTH_PAM_MAILSPOOL_DIR  MAILSPOOL_DIR

/* Config directive auth-pam-mail-group */
#undef  AUTH_PAM_MAIL_GID

/* Config directive auth-pam-facility */
#define AUTH_PAM_FACILITY       "tpop3d"

int         auth_pam_init(void);
authcontext auth_pam_new_user_pass(const char *user, const char *pass);
void        auth_pam_close(void);

#endif /* AUTH_PAM */

#endif /* __AUTH_PAM_H_ */
