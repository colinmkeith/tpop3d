/*
 * listener.h:
 * Objects representing addresses on which to listen.
 *
 * Copyright (c) 2001 Chris Lightfoot.
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

#ifndef __LISTENER_H_ /* include guard */
#define __LISTENER_H_

#include <sys/types.h>

#ifdef MASS_HOSTING
#include <regex.h>
#endif

#ifdef USE_TLS
#include <openssl/err.h>
#include <openssl/ssl.h>
enum tls_mode { none = 0, immediate, stls };
#endif

/* For virtual-domains support, we need to find the address and domain name
 * associated with a socket on which we are listening. */
typedef struct _listener {
    struct sockaddr_in sin;
    char *domain;
#ifdef MASS_HOSTING
    int have_re;
    regex_t re;
    char *regex;    /* string form of RE */
#endif
#ifdef USE_TLS
    struct {
        enum tls_mode mode;
        SSL_CTX *ctx;
    } tls;
#endif
    int s;
    int s_index;
} *listener;

/* the arguments of the constructor vary according to the particular
 * compile-time options. */
listener listener_new(const struct sockaddr_in *addr, const char *domain
#ifdef MASS_HOSTING
 /* leading comma-- yuk */  , const char *regex
#endif
#ifdef USE_TLS
                            , enum tls_mode mode,
                              const char *certfile, const char *pkeyfile
#endif
                        );

#ifdef MASS_HOSTING
char *listener_obtain_domain(listener L, int s);
#endif

void listener_delete(listener L);


#endif /* __LISTENER_H_ */
