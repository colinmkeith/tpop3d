/*
 * auth_other.h:
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
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
authcontext auth_other_new_apop(const char *name, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *host);
authcontext auth_other_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *host);
void auth_other_onlogin(const authcontext A, const char *host);

#endif /* AUTH_OTHER */

#endif /* __AUTH_OTHER_H_ */
