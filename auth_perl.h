/*
 * auth_perl.h:
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __AUTH_PERL_H_ /* include guard */
#define __AUTH_PERL_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_PERL

#include "authswitch.h"
#include "stringmap.h"

/* auth_perl.c */
void xs_init(void);
int auth_perl_init(void);
void auth_perl_close(void);
void auth_perl_postfork(void);
stringmap auth_perl_callfn(const char *perlfn, const int nvars, ...);
authcontext auth_perl_new_apop(const char *name, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost, const char *serverhost);
authcontext auth_perl_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost);
void auth_perl_onlogin(const authcontext A, const char *clienthost, const char *serverhost);

#endif /* AUTH_PERL */

#endif /* __AUTH_PERL_H_ */
