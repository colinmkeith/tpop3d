/*
 * ioabs_tcp.c:
 * I/O abstraction layer for TCP.
 *
 * Copyright (c) 2002 Chris Lightfoot. All rights reserved.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
 *
 */

static const char rcsid[] = "$Id$";

#include <sys/types.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>

#include "connection.h"

/* ioabs_tcp_read:
 * Read using read(2). */
static ssize_t ioabs_tcp_read(connection c, void *buf, size_t count) {
    ssize_t n;
    struct ioabs_tcp *io;
    io = (struct ioabs_tcp*)c->io;
    do
        n = read(c->s, buf, count);
    while (n == -1 && errno == EINTR);
    if (n == -1) {
        if (errno == EAGAIN)
            return IOABS_WOULDBLOCK;
        else {
            io->x_errno = errno;
            return IOABS_ERROR;
        }
    } else
        return n;
}

/* ioabs_tcp_write:
 * Write using write(2). */
static ssize_t ioabs_tcp_write(connection c, const void *buf, size_t count) {
    ssize_t n;
    struct ioabs_tcp *io;
    io = (struct ioabs_tcp*)c->io;
    do
        n = write(c->s, buf, count);
    while (n == -1 && errno == EINTR);
    if (n == -1) {
        if (errno == EAGAIN)
            return IOABS_WOULDBLOCK;
        else {
            io->x_errno = errno;
            return IOABS_ERROR;
        }
    } else
        return n;
}

/* ioabs_tcp_strerror:
 * Return the error string in the saved copy of errno. */
static char *ioabs_tcp_strerror(connection c) {
    struct ioabs_tcp *io;
    io = (struct ioabs_tcp*)c->io;
    return strerror(io->x_errno);
}

/* ioabs_tcp_pre_select:
 * Simple pre-select handling for TCP. */
static void ioabs_tcp_pre_select(connection c, int *n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    struct ioabs_tcp *io;
    io = (struct ioabs_tcp*)c->io;

    FD_SET(c->s, readfds);
    if (c->wrb.p > c->wrb.buffer)
        FD_SET(c->s, writefds);
    
    if (c->s > *n)
        *n = c->s;
}

/* ioabs_tcp_post_select:
 * Simple post-select handling for TCP. */
static int ioabs_tcp_post_select(connection c, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    int r = 0;
    struct ioabs_tcp *io;
    io = (struct ioabs_tcp*)c->io;

    return ioabs_generic_post_select(FD_ISSET(c->s, readfds), FD_ISSET(c->s, writefds));
}

/* ioabs_tcp_destroy:
 * The only resource to be destroyed is the memory allocated for the
 * structure. */
static void ioabs_tcp_destroy(connection c) {
    xfree(c->io);
}

/* ioabs_tcp_shutdown:
 * Shut down the socket connection. */
static int ioabs_tcp_shutdown(connection c) {
    shutdown(c->s, 2);
    close(c->s);
    c->cstate = closed;
    c->s = -1;
    return 1;   /* assume this succeeded. */
}

/* ioabs_tcp_create:
 * Create a struct ioabs_tcp. */
struct ioabs_tcp *ioabs_tcp_create(void) {
    struct ioabs_tcp *io;
    io = malloc(sizeof *io);
    io->und.read        = ioabs_tcp_read;
    io->und.write       = ioabs_tcp_write;
    io->und.strerror    = ioabs_tcp_strerror;
    io->und.pre_select  = ioabs_tcp_pre_select;
    io->und.post_select = ioabs_tcp_post_select;
    io->und.destroy     = ioabs_tcp_destroy;
    io->und.permit_immediate_writes = 1;
    io->x_errno = 0;
    return io;
}
