/*
 * auth_passwd.h: authentication from /etc/passwd
 *
 * This shouldn't be used on modern systems. It's here basically as an
 * example.
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

#ifndef __AUTH_PASSWD_H_ /* include guard */
#define __AUTH_PASSWD_H_

#include "authswitch.h"

#define AUTH_PASSWD_MAILSPOOL_DIR "/var/spool/mail"
#undef  AUTH_PASSWD_MAIL_GID

int         auth_passwd_init();
authcontext auth_passwd_new_user_pass(const char *user, const char *pass);
void        auth_passwd_close();

#endif /* __AUTH_PASSWD_H_ */
