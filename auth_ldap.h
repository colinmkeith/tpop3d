/*
 * auth_ldap.h:
 * Authenticate users against an LDAP server.
 *
 * designed for tpop3d by Sebastien THOMAS (prune@lecentre.net) - Mad Cow tribe
 * Copyright (c) 2002 Sebastien Thomas, Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __AUTH_LDAP_H_ /* include guard */
#define __AUTH_LDAP_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_LDAP

#include "authswitch.h"

int auth_ldap_init(void);
authcontext auth_ldap_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost);
void auth_ldap_close(void);
void auth_ldap_postfork(void);

#endif /* AUTH_LDAP */

#endif /* __AUTH_LDAP_H_ */
