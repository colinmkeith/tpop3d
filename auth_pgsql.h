/*
 * auth_pgsql.h: authenticate users against a Postgres database
 *
 * Copyright (c) 2003 Chris Lightfoot, Stephen White. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __AUTH_PGSQL_H_ /* include guard */
#define __AUTH_PGSQL_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_PGSQL

#include "authswitch.h"

/* The username, password, database and host for the database must be
 * specified in the config file, using the directives
 *
 * auth-pgsql-username
 * auth-pgsql-password
 * auth-pgsql-database
 * auth-pgsql-hostname      (assumed to be "localhost" if unspecified)
 */

/* Config directive: auth-pg-mail-group */
#undef AUTH_PGSQL_MAIL_GID

int  auth_pgsql_init(void);

/* These use SELECT statements defined in auth_pgsql.c */
authcontext auth_pgsql_new_apop(const char *name, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost, const char *serverhost);
authcontext auth_pgsql_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost);
void auth_pgsql_onlogin(const authcontext A, const char *clienthost, const char *serverhost);
void auth_pgsql_postfork(void);
void auth_pgsql_close(void);

#endif /* AUTH_PGSQL */

#endif /* __AUTH_PGSQL_H_ */
