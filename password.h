/*
 * password.h:
 * Verify a submitted password against the real one, subject to
 * interpretation of an optional {scheme} prefix.
 *
 * Copyright (c) 2001 Chris Lightfoot.
 * Refactoring (c) 2003 Paul Makepeace.
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

#ifndef __PASSWORD_H_ /* include guard */
#define __PASSWORD_H_

/* password.c */
int check_password(const char *who, const char *pwhash, const char *pass, const char *default_crypt_scheme);
int check_password_apop(const char *who, const char *pwhash, const char *timestamp, const unsigned char *digest);

#endif /* __PASSWORD_H_ */
