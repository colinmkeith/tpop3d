/*
 * auth_mysql.h: authenticate users against a MySQL database
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.2  2000/10/28 14:57:04  chris
 * Minor changes.
 *
 * Revision 1.1  2000/10/02 18:20:19  chris
 * Initial revision
 *
 *
 */

#ifndef __AUTH_MYSQL_H_ /* include guard */
#define __AUTH_MYSQL_H_

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

int  auth_mysql_init();

/* These use SELECT statements defined in auth_mysql.c */
authcontext auth_mysql_new_apop(const char *name, const char *timestamp, const unsigned char *digest);
authcontext auth_mysql_new_user_pass(const char *user, const char *pass);
void auth_mysql_close();

#endif /* AUTH_MYSQL */

#endif /* __AUTH_MYSQL_H_ */
