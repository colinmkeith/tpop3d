/*
 * auth_other.h:
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

#ifndef __AUTH_OTHER_H_ /* include guard */
#define __AUTH_OTHER_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_OTHER

#include <sys/time.h>

#include "authswitch.h"
#include "stringmap.h"

/* auth_other.c */
int auth_other_start_child(void);
void auth_other_kill_child(void);
int auth_other_init(void);
void auth_other_postfork(void);
void auth_other_close(void);
int auth_other_send_request(const int nvars, ...);
stringmap auth_other_recv_response(void);
authcontext auth_other_new_apop(const char *name, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost, const char *serverhost);
authcontext auth_other_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost);
void auth_other_onlogin(const authcontext A, const char *clienthost, const char *serverhost);

#endif /* AUTH_OTHER */

#endif /* __AUTH_OTHER_H_ */
