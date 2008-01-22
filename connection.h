/*
 * connection.h:
 * connection to the pop3 server
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

#ifndef __CONNECTION_H_ /* include guard */
#define __CONNECTION_H_

#include <pwd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "poll.h"

#include "authswitch.h"
#include "buffer.h"
#include "listener.h"
#include "mailbox.h"
#include "tokenise.h"
#include "vector.h"

#define MAX_POP3_LINE       1024        /* should be sufficient */

#define MAX_AUTH_TRIES      3
#define MAX_ERRORS          8

enum pop3_state {authorisation, transaction, update};
enum conn_state {running, closing, closed};

struct ioabs;

typedef struct _connection {
    int s;                  /* connected socket                 */
    struct sockaddr_in sin; /* name of peer                     */
    char *remote_ip;        /* ASCII remote IP address          */
    struct sockaddr_in sin_local; /* name of local side         */
    char *local_ip;         /* ASCII local IP address           */
    char *idstr;            /* some identifying information     */
    size_t nrd, nwr;        /* number of bytes read/written     */
    
    char *domain;           /* associated domain suffix         */
    char *timestamp;        /* the rfc1939 "timestamp" we emit  */

    buffer rdb;             /* data read from peer              */
    buffer wrb;             /* data to write to peer            */

    int secured;            /* is this a secured connection?    */
    
    struct ioabs *io;       /* I/O abstraction structure        */

    enum conn_state cstate; /* state of underlying transport    */

    enum pop3_state state;  /* from rfc1939                     */

    time_t idlesince;       /* used to implement timeouts       */
    time_t frozenuntil;     /* used to implement freeze on wrong password. */
    int do_shutdown;        /* shutdown after thaw?             */

    int n_auth_tries, n_errors;
    char *user, *pass;      /* authentication state accumulated */
    authcontext a;
    mailbox m;

    listener l;             /* need listener for STLS           */
} *connection;

/* struct ioabs:
 * This represents an abstraction of I/O; it is intended to permit the use
 * of, say, TLS with a connection. */
struct ioabs {
    /* return codes; must be negative */
#define IOABS_WOULDBLOCK        ((ssize_t)-1)
#define IOABS_ERROR             ((ssize_t)-2)

    /* immediate_write CONNECTION BUFFER COUNT
     * Immediately write COUNT bytes from BUFFER to CONNECTION. Returns the
     * number of bytes written on success (may be less than COUNT),
     * IOABS_WOULDBLOCK if the write cannot complete immediately, or
     * IOABS_ERROR if a fatal error occurred. */
    ssize_t (*immediate_write)(connection c, const void *buf, size_t count);

    /* pre_ and post_select are called before and after select(2) in the main
     * loop, and should do all I/O related processing. Frozen connection
     * handling is done in the calling code, so these should address only
     * buffering and state issues. post_select should return a combination of
     * the flags defined below, as well as doing any I/O-layer specific
     * handling. */
    void (*pre_select)(connection c, int *n, struct pollfd *pfds);
    
    /* post_select:
     * Do handling after select has completed. Returns 1 if new data have been
     * read, 0 if not. May alter the connection_state of the associated
     * connection. */
    int (*post_select)(connection c, struct pollfd *pfds);

    /* shutdown:
     * Shut down the connection. Returns zero on success, IOABS_WOULDBLOCK if
     * the operation is in progress, and IOABS_ERROR on error. On return the
     * connection_state of the associated connection will be set to closing or
     * closed, even if an error occurred. */
    int (*shutdown)(connection c);

    /* destroy:
     * Deallocate the structure and free any associated resources. */
    void (*destroy)(connection c);
};

/* struct ioabs_tcp:
 * I/O abstraction for straight TCP. */
struct ioabs_tcp {
    struct ioabs und;
};

/* in ioabs_tcp.c */
struct ioabs_tcp *ioabs_tcp_create(void);

#ifdef USE_TLS
/* TLS support through OpenSSL. */
#include <openssl/ssl.h>

/* struct ioabs_tls:
 * I/O abstraction for TLS. */
struct ioabs_tls {
    struct ioabs und;
    SSL *ssl;
    /* state */
    int accept_blocked_on_write, accept_blocked_on_read;
    int read_blocked_on_write, write_blocked_on_read;
    int shutdown_blocked_on_write, shutdown_blocked_on_read;
};

struct ioabs_tls *ioabs_tls_create(connection c, listener l);

#endif /* USE_TLS */


/* From rfc1939 */
enum pop3_command_code {UNKNOWN,
                        APOP, DELE, LIST,
                        NOOP, PASS, QUIT,
                        RETR, RSET, STAT,
                        STLS, TOP,  UIDL,
                        USER, LAST, CAPA};
    
typedef struct _pop3command {
    enum pop3_command_code cmd;
    tokens toks;
} *pop3command;

/* Create/destroy connections */
connection connection_new(int s, const struct sockaddr_in *sin, listener L);
void connection_delete(connection c);

/* Read data out of the socket into the buffer */
ssize_t connection_read(connection c);

/* Write data from buffer to socket. */
ssize_t connection_write(connection c);

/* Is a connection frozen? */
int connection_isfrozen(connection c);

/* Shut down a connection. */
int connection_shutdown(connection c);

/* Send arbitrary data to the client. */
ssize_t connection_send(connection c, const char *data, const size_t l);

/* Send a response, given in s (without the trailing \r\n) */
int connection_sendresponse(connection c, const int success, const char *s);

/* Send a line, given in s (without the trailing \r\n) */
int connection_sendline(connection c, const char *s);

/* Freeze a connection briefly. */
void connection_freeze(connection c);

/* Attempt to parse a connection from a peer, returning NULL if no command was
 * parsed. */
pop3command connection_parsecommand(connection c);

enum connection_action { do_nothing, close_connection, fork_and_setuid };

/* Do a command */
enum connection_action connection_do(connection c, const pop3command p);

/* Open the mailspool etc. */
int connection_start_transaction(connection c);

/* Commands */
pop3command pop3command_new(const char *s);
void        pop3command_delete(pop3command p);

/* Send a message from a file to a peer. */
int connection_sendmessage(connection c, int fd, size_t msgoffset, size_t skip, size_t msglength, int n);

#endif /* __CONNECTION_H_ */
