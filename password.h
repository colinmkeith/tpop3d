/*
 * password.h:
 * Verify a submitted password against the real one, subject to
 * interpretation of an optional {scheme} prefix.
 *
 * Copyright (c) 2001 Chris Lightfoot.
 * Refactoring (c) 2003 Paul Makepeace.
 * All rights reserved.
 *
 * $Id$
 */

#ifndef __PASSWORD_H_ /* include guard */
#define __PASSWORD_H_

/* password.c */
int check_password(const char *who, const char *pwhash, const char *pass, const char *default_crypt_scheme);
int check_password_apop(const char *who, const char *pwhash, const char *timestamp, const unsigned char *digest);

#endif /* __PASSWORD_H_ */
