/*
 * listener.h:
 * Objects representing addresses on which to listen.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __LISTENER_H_ /* include guard */
#define __LISTENER_H_

#ifdef MASS_HOSTING
#include <regex.h>
#endif

#ifdef TPOP3D_TLS
enum { none, immediate, stls } tls_mode;
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
#ifdef TPOP3D_TLS
    struct {
        tls_mode tls_mode;
        SSL_CTX *ctx;
    } tls;
#endif
    int s;
} *listener;

/* the arguments of the constructor vary according to the particular
 * compile-time options. */
listener listener_new(const struct sockaddr_in *addr, const char *domain
#ifdef MASS_HOSTING
 /* leading comma-- yuk */  , const char *regex
#endif
#ifdef TPOP3D_TLS
                            , tls_mode mode,
                              const char *certfile, const char *pkeyfile
#endif
                        );

#ifdef MASS_HOSTING
    listener listener_new(const struct sockaddr_in *addr, const char *domain, const char *regex);
    char *listener_obtain_domain(listener l, int s);
#else
    listener listener_new(const struct sockaddr_in *addr, const char *domain);
#endif
void listener_delete(listener L);


#endif /* __LISTENER_H_ */
