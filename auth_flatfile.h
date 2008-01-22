/*
 * auth_flatfile.h:
 * Authenticate users using an alternate passwd file
 *
 * designed for tpop3d by Angel Marin <anmar@gmx.net> 
 * Copyright (c) 2002 Angel Marin, Chris Lightfoot.
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
