/*
 * auth_mysql.h: authenticate users against a MySQL database
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __AUTH_MYSQL_H_ /* include guard */
#define __AUTH_MYSQL_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_MYSQL

#include "authswitch.h"

/* The username, password, database and host for the database must be
 * specified in the config file, using the directives
 *
 * auth-mysql-username
 * auth-mysql-password
 * auth-mysql-database
 * auth-mysql-hostname      (assumed to be "localhost" if unspecified)
 */

/* Config directive: auth-mysql-mail-group */
#undef AUTH_MYSQL_MAIL_GID

int  auth_mysql_init(void);

/* These use SELECT statements defined in auth_mysql.c */
authcontext auth_mysql_new_apop(const char *name, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *host);
authcontext auth_mysql_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *host);
void auth_mysql_onlogin(const authcontext A, const char *host);
void auth_mysql_postfork(void);
void auth_mysql_close(void);

#endif /* AUTH_MYSQL */

#endif /* __AUTH_MYSQL_H_ */
