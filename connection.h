/*
 * connection.h:
 * connection to the pop3 server
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __CONNECTION_H_ /* include guard */
#define __CONNECTION_H_

#include <pwd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "authswitch.h"
#include "mailbox.h"
#include "tokenise.h"
#include "vector.h"

#define MAX_POP3_LINE       1024        /* should be sufficient */

#define MAX_AUTH_TRIES      3
#define MAX_ERRORS          8

enum pop3_state {authorisation, transaction, update}; 

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
    
    struct {
        char *buffer;       /* buffer                           */
        char *p;            /* where we've got to in the buffer */
        size_t bufferlen;   /* size of buffer allocated         */
    }   rdb,                /* buffer for reading from peer     */
        wrb;                /* buffer for writing to peer       */

    struct ioabs *io;       /* I/O abstraction structure        */

    char *timestamp;        /* the rfc1939 "timestamp" we emit  */

    enum pop3_state state;  /* from rfc1939                     */

    time_t idlesince;       /* used to implement timeouts       */
    time_t frozenuntil;     /* used to implement freeze on wrong password. */
    int closing;            /* implement delayed close when frozen. */

    int n_auth_tries, n_errors;
    char *user, *pass;      /* state accumulated                */
    authcontext a;
    mailbox m;
} *connection;

/* struct ioabs:
 * This represents an abstraction of I/O; it is intended to permit the use
 * of, say, TLS with a connection. */
struct ioabs {
    /* return codes; must be negative */
#define IOABS_WOULDBLOCK        ((ssize_t)-1)
#define IOABS_ERROR             ((ssize_t)-2)

    /* read:
     * Read data from the connection. Returns the number of bytes read on
     * success, zero if the connection is closed gracefully, IOABS_WOULDBLOCK
     * if the read would block, or IOABS_ERROR if a fatal error occurred. */
    ssize_t (*read)(connection c, void *buf, size_t count);

    /* write:
     * Write data to the connection. Returns the number of bytes read on
     * success, IOABS_WOULDBLOCK if the write would block, or IOABS_ERROR if
     * a fatal error occurred. */
    ssize_t (*write)(connection c, const void *buf, size_t count);

    /* strerror:
     * Obtain an error string representing the last error which occurred on
     * this connection. This should be called only after read or write return
     * IOABS_ERROR, and before calling any other I/O function on this
     * connection. */
    char* (*strerror)(connection c);

    /* pre_ and post_select are called before and after select(2) in the main
     * loop, and should do all I/O related processing. Frozen connection
     * handling is done in the calling code, so these should address only
     * buffering and state issues. post_select should return a combination of
     * the flags defined below, as well as doing any I/O-layer specific
     * handling. */
    void (*pre_select)(connection c, int *n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
#define IOABS_TRY_READ  1
#define IOABS_TRY_WRITE 2
    int (*post_select)(connection c, fd_set *readfds, fd_set *writefds, fd_set *exceptfds);

    /* should a write be tried immediately on connection_send, or should all
     * output be buferred? */
    int permit_immediate_writes;
};

/* struct ioabs_tcp:
 * I/O abstraction for straight TCP. */
struct ioabs_tcp {
    struct ioabs und;
    int x_errno;    /* can't be called errno as that's a macro in Linux */
};

/* in ioabs_tcp.c */
struct ioabs_tcp *ioabs_tcp_create(void);

#ifdef TPOP3D_TLS
/* TLS support through OpenSSL. */
#include <openssl.h>

/* struct ioabs_tls:
 * I/O abstraction for TLS. */
struct ioabs_tls {
    struct ioabs und;
    SSL *ssl;
    /* saved errno, saved value of ERR_get_error and of SSL_get_error */
    int x_errno, ssl_err, ssl_io_err;
    /* state */
    int read_blocked_on_write, write_blocked_on_read;
};

#endif /* TPOP3D_TLS */


/* From rfc1939 */
enum pop3_command_code {UNKNOWN,
                        APOP, DELE, LIST,
                        NOOP, PASS, QUIT,
                        RETR, RSET, STAT,
                        TOP,  UIDL, USER,
                        LAST};
    
typedef struct _pop3command {
    enum pop3_command_code cmd;
    tokens toks;
} *pop3command;

/* Create/destroy connections */
connection   connection_new(const int s, const struct sockaddr_in *sin, const char *domain);
void         connection_delete(connection c);

/* Read data out of the socket into the buffer */
ssize_t connection_read(connection c);

/* Write data from buffer to socket. */
ssize_t connection_write(connection c);

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
