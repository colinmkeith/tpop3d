/*
 * ioabs_tcp.c:
 * I/O abstraction layer for TCP.
 *
 * Copyright (c) 2002 Chris Lightfoot.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
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

static const char rcsid[] = "$Id$";

#include <sys/types.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "poll.h"

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
    if (c->cstate == closed)
        return IOABS_ERROR;
    do
        n = write(c->s, buf, count);
    while (n == -1 && errno == EINTR);
    if (n > 0) {
        c->nwr += n;
        c->idlesince = time(NULL);
    }
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
static void ioabs_tcp_pre_select(connection c, int *n, struct pollfd *pfds) {
    struct ioabs_tcp *io;
    io = (struct ioabs_tcp*)c->io;

    pfds[c->s_index].fd = c->s;
    pfds[c->s_index].events |= POLLIN;
    if (buffer_available(c->wrb) > 0)
       pfds[c->s_index].events |= POLLOUT;

    if (c->s_index > *n)
       *n = c->s_index;
}

/* ioabs_tcp_post_select:
 * Simple post-select handling for TCP. */
static int ioabs_tcp_post_select(connection c, struct pollfd *pfds) {
    int ret = 0;
    ssize_t n;
    struct ioabs_tcp *io;
    io = (struct ioabs_tcp*)c->io;

    if (pfds[c->s_index].revents & (POLLIN | POLLHUP)) {
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

    if (pfds[c->s_index].revents & POLLOUT && buffer_available(c->wrb) > 0) {
        /* Can write data. */
        n = 1;
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
                c->idlesince = time(NULL);
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
