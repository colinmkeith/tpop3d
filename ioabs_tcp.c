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
#include <syslog.h>
#include <unistd.h>

#include <sys/select.h>

#include "connection.h"
#include "util.h"

/* ioabs_tcp_shutdown:
 * Shut down the socket connection. */
static int ioabs_tcp_shutdown(connection c) {
    shutdown(c->s, 2);
    close(c->s);
    c->cstate = closed;
    c->s = -1;
    return 1;   /* assume this succeeded. */
}

/* ioabs_tcp_immediate_write:
 * Write using write(2). */
static ssize_t ioabs_tcp_immediate_write(connection c, const void *buf, size_t count) {
    ssize_t n;
    struct ioabs_tcp *io;
    io = (struct ioabs_tcp*)c->io;
    do
        n = write(c->s, buf, count);
    while (n == -1 && errno == EINTR);
    if (n > 0)
        c->nwr += n;
    if (n == -1) {
        if (errno == EAGAIN)
            return IOABS_WOULDBLOCK;
        else {
            log_print(LOG_ERR, _("ioabs_tcp_immediate_write: client %s: write: %m; closing connection"), c->idstr);
            ioabs_tcp_shutdown(c);
            return IOABS_ERROR;
        }
    } else
        return n;
}

/* ioabs_tcp_pre_select:
 * Simple pre-select handling for TCP. */
static void ioabs_tcp_pre_select(connection c, int *n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    struct ioabs_tcp *io;
    io = (struct ioabs_tcp*)c->io;

    FD_SET(c->s, readfds);
    if (buffer_available(c->wrb) > 0)
        FD_SET(c->s, writefds);
    
    if (c->s > *n)
        *n = c->s;
}

/* ioabs_tcp_post_select:
 * Simple post-select handling for TCP. */
static int ioabs_tcp_post_select(connection c, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    int ret = 0;
    ssize_t n;
    struct ioabs_tcp *io;
    io = (struct ioabs_tcp*)c->io;

    if (FD_ISSET(c->s, readfds)) {
        /* Can read data. */
        do {
            char *r;
            size_t rlen;
            /* Ensure that we have lots of space to read.... */
            buffer_expand(c->rdb, MAX_POP3_LINE);
            r = buffer_get_push_ptr(c->rdb, &rlen);
            do
                n = read(c->s, r, rlen);
            while (n == -1 && errno == EINTR);
            if (n > 0) {
                buffer_push_bytes(c->rdb, n);
                c->nrd += n;
                ret = 1;
            }
        } while (n > 0);
        if (n == 0) {
            /* Connection has been closed. */
            log_print(LOG_INFO, _("ioabs_tcp_post_select: client %s: connection closed by peer"), c->idstr);
            ioabs_tcp_shutdown(c);
            return 0;
        } else if (n == -1 && errno != EAGAIN) {
            log_print(LOG_ERR, _("ioabs_tcp_post_select: client %s: read: %m; closing connection"), c->idstr);
            ioabs_tcp_shutdown(c);
            return 0;
        }
    }

    if (FD_ISSET(c->s, writefds) && buffer_available(c->wrb) > 0) {
        /* Can write data. */
        do {
            char *w;
            size_t wlen;
            if (!(w = buffer_get_consume_ptr(c->wrb, &wlen)))
                break; /* no more data to write */
            do
                n = write(c->s, w, wlen);
            while (n == -1 && errno == EINTR);
            if (n > 0) {
                buffer_consume_bytes(c->wrb, n);
                c->nwr += n;
            }
        } while (n > 0);
        if (n == -1 && errno != EAGAIN) {
            log_print(LOG_ERR, _("ioabs_tcp_post_select: client %s: write: %m; closing connection"), c->idstr);
            ioabs_tcp_shutdown(c);
        }
    }

    return ret;
}

/* ioabs_tcp_destroy:
 * The only resource to be destroyed is the memory allocated for the
 * structure. */
static void ioabs_tcp_destroy(connection c) {
    xfree(c->io);
}

/* ioabs_tcp_create:
 * Create a struct ioabs_tcp. */
struct ioabs_tcp *ioabs_tcp_create(void) {
    struct ioabs_tcp *io;
    io = xmalloc(sizeof *io);
    io->und.immediate_write = ioabs_tcp_immediate_write;
    io->und.pre_select      = ioabs_tcp_pre_select;
    io->und.post_select     = ioabs_tcp_post_select;
    io->und.shutdown        = ioabs_tcp_shutdown;
    io->und.destroy         = ioabs_tcp_destroy;
    return io;
}
