/*
 * ioabs_tls.c:
 * I/O abstraction layer for TLS/SSL.
 *
 * Copyright (c) 2002 Chris Lightfoot. All rights reserved.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
 *
 */

#ifdef TPOP3D_TLS

static const char rcsid[] = "$Id$";

#include <sys/types.h>

#include <syslog.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <sys/select.h>

#include "connection.h"
#include "listener.h"
#include "util.h"

/* 
 * This is a bit fragile because, in non-blocking mode, SSL_read and SSL_write
 * may return SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE. In these cases we're
 * supposed to wait until the socket becomes available for reading/writing and
 * then call the function again. When the function is called again, we must
 * call it with the same arguments as before (though we are permitted to append
 * data to the buffer to be sent when we do so, and move the buffer so long as
 * we set SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER). To permit immediate writes, we
 * try the write and copy the data into the write buffer if it fails. Since 
 * otherwise we will never call SSL_read and SSL_write other than on the
 * connection's read and write buffers, the whole thing does work. But what a
 * mess....
 */

/* underlying_shutdown CONNECTION
 * Shut down the underlying transport for CONNECTION. */
static void underlying_shutdown(connection c) {
    shutdown(c->s, 2);
    close(c->s);
    c->s = -1;
    c->cstate = closed;
}

/* ioabs_tls_shutdown CONNECTION
 * Start the TLS shutdown in motion. */
static int ioabs_tls_shutdown(connection c) {
    int n, e;
    struct ioabs_tls *io;
    io = (struct ioabs_tls*)c->io;
    
    n = SSL_shutdown(io->ssl);
    
    if (n == 1) {
        underlying_shutdown(c);
        return 0;     /* shutdown successful */
    }

    e = ERR_get_error();
    switch (SSL_get_error(io->ssl, n)) {
        case SSL_ERROR_WANT_READ:
            c->cstate = closing;
            io->shutdown_blocked_on_read = 1;
            return IOABS_WOULDBLOCK;

        case SSL_ERROR_WANT_WRITE:
            c->cstate = closing;
            io->shutdown_blocked_on_write = 1;
            return IOABS_WOULDBLOCK;
            
        case SSL_ERROR_ZERO_RETURN:
            /* Connection closed OK. */
            underlying_shutdown(c);
            return 0;

        case SSL_ERROR_SYSCALL:
            if (!e) {
                if (n == 0)
                    log_print(LOG_ERR, _("ioabs_tls_shutdown: client %s: connection unexpectedly closed by peer"), c->idstr);
                else
                    log_print(LOG_ERR, _("ioabs_tls_shutdown: client %s: %m"), c->idstr);
                break;
            }
            /* fall through */
        default:
            log_print(LOG_ERR, _("ioabs_tls_shutdown: client %s: %s"), c->idstr, ERR_reason_error_string(e));
            break;
    }

    /* If we've got to here, a fatal error has occurred. */
    underlying_shutdown(c);
    return IOABS_ERROR;
}

/* ioabs_tls_read CONNECTION BUFFER COUNT
 * Attempt to read COUNT bytes from CONNECTION into BUFFER. Returns the number
 * of bytes read on success, zero if the connection was gracefully closed,
 * IOABS_WOULDBLOCK if the read would block, and IOABS_ERROR if a fatal error
 * occurred, in which case the connection is shut down. State flags are
 * updated. */
static ssize_t ioabs_tls_read(connection c, void *buf, size_t count) {
    int n, e;
    struct ioabs_tls *io;
    io = (struct ioabs_tls*)c->io;

    n = SSL_read(io->ssl, buf, count);

    if (n > 0) return n;

    e = ERR_get_error();
    switch (SSL_get_error(io->ssl, n)) {
        case SSL_ERROR_WANT_WRITE:
            io->read_blocked_on_write = 1;
            /* fall through */
        case SSL_ERROR_WANT_READ:   /* can this really occur here? */
            return IOABS_WOULDBLOCK;

        case SSL_ERROR_ZERO_RETURN:
            /* TLS connection closed. */
            log_print(LOG_ERR, _("ioabs_tls_read: client %s: connection closed by peer"), c->idstr);
            underlying_shutdown(c);
            return 0;

        case SSL_ERROR_SYSCALL:
            if (!e) {
                if (n == 0)
                    log_print(LOG_ERR, _("ioabs_tls_read: client %s: connection unexpectedly closed by peer"), c->idstr);
                else
                    log_print(LOG_ERR, _("ioabs_tls_read: client %s: %m; closing connection"), c->idstr);
                break;
            }
            /* fall through */
        case SSL_ERROR_SSL:
        default:
            log_print(LOG_ERR, _("ioabs_tls_read: client %s: %s; closing connection"), c->idstr, ERR_reason_error_string(e));
            break;
    }
    
    underlying_shutdown(c);
    return IOABS_ERROR;
}

/* ioabs_tls_immediate_write CONNECTION BUFFER COUNT
 * Attempt to write COUNT bytes from BUFFER to CONNECTION. Returns the number
 * of bytes written on success, IOABS_WOULDBLOCK if the write would block, and
 * IOABS_ERROR if a fatal error occurred, in which case the connection is shut
 * down. State flags are updated. */
static ssize_t ioabs_tls_immediate_write(connection c, const void *buf, size_t count) {
    int n, e;
    struct ioabs_tls *io;
    io = (struct ioabs_tls*)c->io;
    
    n = SSL_write(io->ssl, buf, count);

    if (n > 0) return n;

    e = ERR_get_error();
    switch (SSL_get_error(io->ssl, n)) {
        case SSL_ERROR_WANT_READ:
            io->write_blocked_on_read = 1;
            /* fall through */
        case SSL_ERROR_WANT_WRITE:
            return IOABS_WOULDBLOCK;

        case SSL_ERROR_ZERO_RETURN:
            /* TLS connection closed. */
            log_print(LOG_ERR, _("ioabs_tls_read: client %s: connection closed by peer"), c->idstr);
            underlying_shutdown(c);
            return IOABS_ERROR;

        case SSL_ERROR_SYSCALL:
            if (!e) {
                if (n == 0)
                    log_print(LOG_ERR, _("ioabs_tls_read: client %s: connection unexpectedly closed by peer"), c->idstr);
                else
                    log_print(LOG_ERR, _("ioabs_tls_read: client %s: %m; closing connection"), c->idstr);
                break;
            }
            /* fall through */
        case SSL_ERROR_SSL:
        default:
            log_print(LOG_ERR, _("ioabs_tls_read: client %s: %s; closing connection"), c->idstr, ERR_reason_error_string(e));
            break;
    }
    
    underlying_shutdown(c);
    return IOABS_ERROR;
}

/* ioabs_tls_pre_select:
 * Pre-select handling for TLS, taking account of the rehandshaking nonsense. */
static void ioabs_tls_pre_select(connection c, int *n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    struct ioabs_tls *io;
    io = (struct ioabs_tls*)c->io;

    FD_SET(c->s, readfds);  /* always want to read */
    if ((!io->write_blocked_on_read && buffer_available(c->wrb) > 0)
        || io->accept_blocked_on_write || io->read_blocked_on_write || io->shutdown_blocked_on_write)
        FD_SET(c->s, writefds);

    if (c->s > *n)
        *n = c->s;
}

/* ioabs_tls_post_select:
 * Post-select handling for TLS, with its complicated logic. */
static int ioabs_tls_post_select(connection c, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    int ret = 0, R = 0;
    ssize_t n;
    int canread, canwrite;
    struct ioabs_tls *io;
    io = (struct ioabs_tls*)c->io;

    canread  = FD_ISSET(c->s, readfds);
    canwrite = FD_ISSET(c->s, writefds);
    
    /* First, accept handling. */
    if ((io->accept_blocked_on_read && canread) || (io->accept_blocked_on_write && canwrite)) {
        int e;
        io->accept_blocked_on_read = io->accept_blocked_on_write = 0;
        if ((R = SSL_accept(io->ssl)) <= 0) {
            e = SSL_get_error(io->ssl, R);
            switch (e) {
                case SSL_ERROR_WANT_READ:
                    io->accept_blocked_on_read = 1;
                    break;

                case SSL_ERROR_WANT_WRITE:
                    io->accept_blocked_on_write = 1;
                    break;

                case SSL_ERROR_ZERO_RETURN:
                    /* TLS connection closed. */
                    log_print(LOG_ERR, _("ioabs_tls_post_select: client %s: SSL_accept: connection closed by peer"), c->idstr);
                    underlying_shutdown(c);
                    return 0;

                case SSL_ERROR_SYSCALL:
                    if (!e) {
                        if (ERR_get_error() == 0)
                            log_print(LOG_ERR, _("ioabs_tls_post_select: client %s: SSL_accept: connection unexpectedly closed by peer"), c->idstr);
                        else
                            log_print(LOG_ERR, _("ioabs_tls_post_select: client %s: SSL_accept: %m; closing connection"), c->idstr);
                        break;
                    }
                    /* fall through */
                case SSL_ERROR_SSL:
                default:
                    log_print(LOG_ERR, _("ioabs_tls_post_select: client %s: SSL_accept: %s; closing connection"), c->idstr, ERR_reason_error_string(ERR_get_error()));
                    /* Just shut down the physical transport, since TLS isn't
                     * up yet. */
                    underlying_shutdown(c);
                    return 0;
            }
        }
    } else if (io->accept_blocked_on_read || io->accept_blocked_on_write) return 0;
    
    /* Next, shutdown processing. */
    if ((io->shutdown_blocked_on_read && canread) || (io->shutdown_blocked_on_write && canwrite)) {
        ioabs_tls_shutdown(c);
        /* If we're in the process of shutting down, do nothing else. */
        return 0;
    }
fprintf(stderr, "  rbow %d wbor %d canread %d canwrite %d buf %d\n", io->read_blocked_on_write, io->write_blocked_on_read, canread, canwrite, buffer_available(c->wrb));

    /* Write from the buffer to the connection, if necessary. */
    if (((!io->write_blocked_on_read && canwrite) || (io->write_blocked_on_read && canread)) && buffer_available(c->wrb) > 0) {
fprintf(stderr, "write!\n");
        io->write_blocked_on_read = 0;
        n = 1;
        do {
            char *w;
            size_t wlen;
            if (!(w = buffer_get_consume_ptr(c->wrb, &wlen)))
                break;  /* no more data to write */
            n = ioabs_tls_immediate_write(c, w, wlen);
            if (n > 0) {
                buffer_consume_bytes(c->wrb, n);
                c->nwr += n;
            }
        } while (n > 0);
        /* Connection may have been closed. */
        if (n <= 0)
            return 0;
    }
fprintf(stderr, "+ rbow %d wbor %d canread %d canwrite %d buf %d\n", io->read_blocked_on_write, io->write_blocked_on_read, canread, canwrite, buffer_available(c->wrb));

    /* Read from the connection into the buffer, if necessary. */
    if ((!io->read_blocked_on_write && canread) || (io->read_blocked_on_write && canwrite)) {
        io->read_blocked_on_write = 0;
        do {
            char *r;
            size_t rlen;
            buffer_expand(c->rdb, MAX_POP3_LINE);
            r = buffer_get_push_ptr(c->rdb, &rlen);
            n = ioabs_tls_read(c, r, rlen);
            if (n > 0) {
                buffer_push_bytes(c->rdb, n);
                c->nrd += n;
                ret = 1;
            }
        } while (n > 0);
        /* Connection may have been closed. */
        if (n == IOABS_ERROR)
            return 0;
    }

    
    return ret;
}

/* ioabs_tls_destroy CONNECTION
 * Destroy the TLS connection structure associated with CONNECTION and free
 * the memory. */
static void ioabs_tls_destroy(connection c) {
    struct ioabs_tls *io;
    io = (struct ioabs_tls*)c->io;
    SSL_free(io->ssl);
    xfree(c->io);
}

/* ioabs_tls_create CONNECTION LISTENER
 * Create a new TLS connection structure for CONNECTION, using the TLS context
 * of LISTENER. */
struct ioabs_tls *ioabs_tls_create(connection c, listener l) {
    struct ioabs_tls *io, i = {0};
    int r;

    if (!l->tls.ctx) return NULL;
    io = xmalloc(sizeof *io);
    *io = i;

    /* 
     * Create the SSL connection, attach it to the socket, and set negotiation
     * in progress. Since we are using nonblocking sockets, negotiation may
     * wind up blocking on read or write. In this case we need to set an
     * appropriate flag and return sucessfully.
     */
    if (!(io->ssl = SSL_new(l->tls.ctx))) {
        log_print(LOG_ERR, _("ioabs_tls_create: client %s: %s"), c->idstr, ERR_reason_error_string(ERR_get_error()));
        xfree(io);
        return NULL;
    }

    SSL_set_fd(io->ssl, c->s);
    
    if ((r = SSL_accept(io->ssl)) <= 0)
        switch (SSL_get_error(io->ssl, r)) {
            case SSL_ERROR_WANT_READ:
                io->accept_blocked_on_read = 1;
                break;

            case SSL_ERROR_WANT_WRITE:
                io->accept_blocked_on_write = 1;
                break;

            default:
                log_print(LOG_ERR, _("ioabs_tls_create: client %s: SSL_accept: %s"), c->idstr, ERR_reason_error_string(SSL_get_error(io->ssl, r)));
                SSL_free(io->ssl);
                xfree(io);
                return NULL;
        }
    
    io->und.immediate_write = ioabs_tls_immediate_write;
    io->und.pre_select      = ioabs_tls_pre_select;
    io->und.post_select     = ioabs_tls_post_select;
    io->und.shutdown        = ioabs_tls_shutdown;
    io->und.destroy         = ioabs_tls_destroy;
    
    return io;
}

#endif /* TPOP3D_TLS */
