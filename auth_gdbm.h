/*
 * auth_gdbm.h:
 * Authenticate users using a GNU dbm file
 *
 * Based on auth_flatfile.h by Angel Marin, designed for tpop3d by
 * Daniel Tiefnig at Inode, Austria. <d.tiefnig@inode.at>
 *
 * Copyright (c) 2004 Daniel Tiefnig. All rights reserved. This
 * software is free software, you can modify and/or redistribute
 * it as tpop3d itself. See the file COPYING in the base directory
 * of your tpop3d distribution.
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
