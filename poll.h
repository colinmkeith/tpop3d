/*
 * poll.h:
 *
 * Copyright (c) 2006 Chris Lightfoot. All rights reserved.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
 *
 * $Id$
 *
 */

#ifndef __POLL_H_ /* include guard */
#define __POLL_H_

#ifdef HAVE_POLL

#include <sys/poll.h>

#else

/* from poll(2) */
#define POLLIN      0x0001    /* There is data to read */
#define POLLPRI     0x0002    /* There is urgent data to read */
#define POLLOUT     0x0004    /* Writing now will not block */
#define POLLERR     0x0008    /* Error condition */
#define POLLHUP     0x0010    /* Hung up */
#define POLLNVAL    0x0020    /* Invalid request: fd not open */
    /* -- actually we only implement POLLIN and POLLOUT... */

struct pollfd {
    int fd;
    short events, revents;
};

int poll(struct pollfd *ufds, unsigned int nfds, int timeout);

#endif

#endif /* __POLL_H_ */
