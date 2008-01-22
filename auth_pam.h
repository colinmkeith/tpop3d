/*
 * auth_pam.h:
 * authenticate using Pluggable Authentication Modules
 *
 * Copyright (c) 2001 Chris Lightfoot.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
authcontext auth_pam_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost);
void        auth_pam_close(void);

#endif /* AUTH_PAM */

#endif /* __AUTH_PAM_H_ */
