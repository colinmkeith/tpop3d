/*
 * poll.c:
 * Limited poll(2) implementation with select(2), for systems which lack it.
 *
 * Copyright (c) 2006 Chris Lightfoot. All rights reserved.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
 *
 */

#ifdef HAVE_CONFIG_H
#include <configuration.h>
#endif

#ifndef HAVE_POLL

static const char rcsid[] = "$Id$";

#include <sys/types.h>

#include <errno.h>
#include <unistd.h>

#include <sys/time.h>

#include "poll.h"

/* poll FDS NUM TIMEOUT
 * Wait for event on the NUM FDS, returning after TIMEOUT milliseconds if no
 * events have occurred, or waiting forever if TIMEOUT is negative. Returns
 * the number of FDS on which there are events pending, or -1 on error. This
 * is an implementation of the standard poll(2) function in terms of select(2),
 * for systems which have the latter but not the former. */
int poll(struct pollfd *ufds, unsigned int nfds, int timeout) {
    fd_set rds, wrs;
    struct timeval tv = {0}, *ptv = NULL;
    unsigned int i;
    int maxfd = -1, res;

    FD_ZERO(&rds);
    FD_ZERO(&wrs);
    
    /* Make a mapping from fd to slot number, and insert the file descriptors
     * in the fd_sets. */
    for (i = 0; i < nfds; ++i) {
        int fd;
        fd = ufds[i].fd;

        if (fd < 0) {
            next;
        }
        
        if (fd > maxfd)
            maxfd = fd;

        ufds[i].revents = 0;
        if (ufds[i].events & POLLIN)
            FD_SET(fd, &rds);
        if (ufds[i].events & POLLOUT)
            FD_SET(fd, &wrs);
    }

    if (timeout >= 0) {
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
        ptv = &tv;
    }
    
    if (-1 == (res = select(maxfd + 1, &rds, &wrs, NULL, ptv)))
        return -1;

    for (i = 0; i < nfds; ++i) {
        int fd;
        fd = ufds[i].fd;

        if (FD_ISSET(fd, &rds))
            /* XXX this is broken -- to comply with the poll(2) semantics we
             * should test for EOF as well, and set POLLHUP if true. How can
             * we do that sanely, though? */
            ufds[i].revents |= POLLIN;
        if (FD_ISSET(fd, &wrs))
            ufds[i].revents |= POLLOUT;
    }

    return res;
}

#endif /* !HAVE_POLL */

