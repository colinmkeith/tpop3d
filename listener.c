/*
 * listener.c:
 * Objects representing addresses on which to listen.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif // HAVE_CONFIG_H

#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "listener.h"
#include "util.h"

/* listener_new:
 * Create a new listener object, listening on the specified address.
 */
listener listener_new(const struct sockaddr_in *addr, const char *domain) {
    listener L;
    struct hostent *he;
    
    L = (listener)malloc(sizeof(struct _listener));
    memset(L, 0, sizeof(struct _listener));
    memcpy(&(L->sin), addr, sizeof(struct sockaddr_in));
    L->s = socket(PF_INET, SOCK_STREAM, 0);
    if (L->s == -1) {
        print_log(LOG_ERR, "listener_new: socket: %m");
        goto fail;
    } else {
        int t = 1;
        if (setsockopt(L->s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t)) == -1) {
            print_log(LOG_ERR, "listener_new: setsockopt: %m");
            goto fail;
        } else if (fcntl(L->s, F_SETFL, O_NONBLOCK) == -1) {
            print_log(LOG_ERR, "listener_new: fcntl: %m");
            goto fail;
        } else if (bind(L->s, (struct sockaddr*)addr, sizeof(struct sockaddr_in)) == -1) {
            print_log(LOG_ERR, "listener_new: bind(%s:%d): %m", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
            goto fail;
        } else if (listen(L->s, SOMAXCONN) == -1) {
            print_log(LOG_ERR, "listener_new: listen: %m");
            goto fail;
        }
    }

    /* Now, we need to find the domain associated with this socket. */
    if (!domain) {
        he = gethostbyaddr((char *)&(addr->sin_addr), sizeof(addr->sin_addr), AF_INET);
        if (!he) {
            print_log(LOG_WARNING, "listener_new: gethostbyaddr(%s): cannot resolve name", inet_ntoa(addr->sin_addr));
            print_log(LOG_WARNING, "listener_new: %s: no domain suffix can be appended for this address", inet_ntoa(addr->sin_addr));
        } else {
            /* We need to find out an appropriate domain suffix for the address.
             * FIXME we just take the first address with a "." in it, and use the
             * part after the ".".
             */
            char **a, *b;
            b = strchr(he->h_name, '.');
            if (b && *(b + 1)) {
                L->domain = strdup(b + 1);
            } else 
                for (a = he->h_aliases; *a; ++a) {
                    char *b;
                    fprintf(stderr, "%s\n", *a);
                    if ((b = strchr(*a, '.')) && *(b + 1)) {
                        L->domain = strdup(b + 1);
                        break;
                    }
                }

            if (!L->domain)
                print_log(LOG_WARNING, "listener_new: %s: no suitable domain suffix found for this address", inet_ntoa(addr->sin_addr));
        }
    } else L->domain = strdup(domain);

    /* Last try; use the nodename from uname(2). */
    if (!L->domain) {
        struct utsname u;
        if (uname(&u) == -1) {
            print_log(LOG_WARNING, "listener_new: uname: %m");
            print_log(LOG_WARNING, "listener_new: %s: using domain suffix `x.invalid'", inet_ntoa(addr->sin_addr));
            L->domain = strdup("x.invalid");
        } else {
            print_log(LOG_WARNING, "listener_new: %s: using fallback domain suffix %s", inet_ntoa(addr->sin_addr), u.nodename);
            L->domain = strdup(u.nodename);
        }
    }

    return L;

fail:
    listener_delete(L);
    return NULL;
}

/* listener_delete:
 * Delete a listener object, closing the associated socket.
 */
void listener_delete(listener L) {
    if (!L) return;
    if (L->s != -1) close(L->s); /* Do not shutdown(2). */
    if (L->domain) free(L->domain);
    free(L);
}


