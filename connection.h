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

    char *timestamp;        /* the rfc1939 "timestamp" we emit  */

    enum pop3_state state;  /* from rfc1939 */

    time_t idlesince;       /* used to implement timeouts */
    time_t frozenuntil;     /* used to implement freeze on wrong password. */
    int closing;            /* implement delayed close when frozen. */

    int n_auth_tries, n_errors;
    char *user, *pass;      /* state accumulated */
    authcontext a;
    mailbox m;
} *connection;

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
