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

/* For virtual-domains support, we need to find the address and domain name
 * associated with a socket on which we are listening.
 */
typedef struct _listener {
    struct sockaddr_in sin;
    char *domain;
    int s;
} *listener;

listener listener_new(const struct sockaddr_in *addr, const char *domain);
void listener_delete(listener L);


#endif /* __LISTENER_H_ */
