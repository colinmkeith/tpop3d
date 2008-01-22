/*
 * auth_gdbm.h:
 * Authenticate users using a GNU dbm file
 *
 * Based on auth_flatfile.h by Angel Marin, designed for tpop3d by
 * Daniel Tiefnig at Inode, Austria. <d.tiefnig@inode.at>
 *
 * Copyright (c) 2004 Daniel Tiefnig.
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

#ifndef __AUTH_GDBM_H_ /* include guard */
#define __AUTH_GDBM_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_GDBM

#include "authswitch.h"

/* auth_gdbm.c */
int auth_gdbm_init(void);
authcontext auth_gdbm_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost);
authcontext auth_gdbm_new_apop(const char *user, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost, const char *serverhost);
void auth_gdbm_postfork(void);
void auth_gdbm_close(void);


#endif /* AUTH_GDBM */

#endif /* __AUTH_GDBM_H_ */
