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
    char *idstr;            /* some identifying information     */
    size_t nrd, nwr;        /* number of bytes read/written     */
    
    char *domain;           /* associated domain suffix         */
    char *buffer;           /* buffer from peer                 */
    char *p;                /* where we've got to in the buffer */
    size_t bufferlen;       /* size of buffer allocated         */

    char *timestamp;        /* the rfc1939 "timestamp" we emit  */

    enum pop3_state state;  /* from rfc1939 */

    time_t idlesince;       /* used to implement timeouts */

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

/* Send a response, given in s (without the trailing \r\n) */
int connection_sendresponse(connection c, const int success, const char *s);

/* Send a line, given in s (without the trailing \r\n) */
int connection_sendline(connection c, const char *s);

/* Attempt to parse a connection from a peer, returning NULL if no command was
 * parsed.
 */
pop3command connection_parsecommand(connection c);

enum connection_action { do_nothing, close_connection, fork_and_setuid };

/* Do a command */
enum connection_action connection_do(connection c, const pop3command p);

/* Open the mailspool etc. */
int connection_start_transaction(connection c);

/* Commands */
pop3command pop3command_new(const char *s);
void        pop3command_delete(pop3command p);

#endif /* __CONNECTION_H_ */
