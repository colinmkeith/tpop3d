/*
 * connection.c: deal with connections from clients
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.4  2000/10/09 18:44:47  chris
 * Minor changes.
 *
 * Revision 1.3  2000/10/02 18:20:19  chris
 * Supports most of POP3.
 *
 * Revision 1.2  2000/09/26 22:23:36  chris
 * Various changes.
 *
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

static const char rcsid[] = "$Id$";

#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "connection.h"

/* make_timestamp:
 * Create a timestamp string.
 */
#define TIMESTAMP_LEN   32
static char hex[] = "0123456789abcdef";

static char *make_timestamp() {
    int fd;
    unsigned char buffer[TIMESTAMP_LEN / 2], *q;
    struct utsname u;
    char *s, *p;
    size_t l;

    if (uname(&u) == -1) return NULL;

    s = (char*)malloc(l = 1 + TIMESTAMP_LEN + 1 + strlen(u.nodename) + 2);
    if (!s) return NULL;
    memset(s, 0, l);
    *s = '<';
    
    fd = open("/dev/urandom", O_RDONLY); /* FIXME Linux specific */
    if (read(fd, buffer, sizeof(buffer)) != sizeof(buffer)) {
        free(s);
        return NULL;
    }
    close(fd);
    
    for (p = s + 1, q = buffer; q < buffer + sizeof(buffer); ++q) {
        *p++ = hex[(((int)*q) >> 4) & 0x0f];
        *p++ = hex[((int)*q) & 0x0f];
    }
    strcat(s, "@");
    strcat(s, u.nodename);
    strcat(s, ">");

    return s;
}

/* connection_new:
 * Create a connection object from a socket.
 */
connection connection_new(int s, const struct sockaddr_in *sin) {
    connection c = 0;
    c = (connection)malloc(sizeof(struct _connection));
    if (!c) return NULL;

    memset(c, 0, sizeof(struct _connection));

    c->s = s;
    memcpy(&(c->sin), sin, sizeof(struct sockaddr_in));

    c->p = c->buffer = (char*)malloc(c->bufferlen = MAX_POP3_LINE);
    if (!c->buffer) goto fail;

    c->timestamp = make_timestamp();
    if (!c->timestamp) goto fail;
    
    c->state = authorisation;

    if (!connection_sendresponse(c, 1, c->timestamp)) goto fail;

    return c;

    fail:
    connection_delete(c);
    return NULL;
}

/* connection_delete:
 * Delete a connection and disconnect the peer.
 */
void connection_delete(connection c) {
    if (!c) return;

    shutdown(c->s, 2);

    if (c->a) authcontext_delete(c->a);
    if (c->m) mailspool_delete(c->m);

    if (c->buffer)    free(c->buffer);
    if (c->timestamp) free(c->timestamp);
    if (c->user)      free(c->user);
    if (c->pass)      free(c->pass);
    free(c);
}

/* connection_read:
 * Read data from the socket into the buffer, if available. Returns -1 on
 * error or buffer full, 0 on EOF or the number of bytes read.
 */
ssize_t connection_read(connection c) {
    ssize_t n;
    if (!c) return;
    if (c->p == c->buffer + c->bufferlen) return -1;
    n = read(c->s, c->p, c->buffer + c->bufferlen - c->p);
    if (n > 0) c->p += n;
    return n;
}

/*
static void dump(const char *s, size_t l) {
    const char *p;
    for (p = s; p < s + l; ++p) {
        if (*p < 32)
            switch(*p) {
            case '\t': fprintf(stderr, "\\t"); break;
            case '\r': fprintf(stderr, "\\r"); break;
            case '\n': fprintf(stderr, "\\n"); break;
            default:   fprintf(stderr, "\\x%02x", *p);
            }
        else fprintf(stderr, "%c", (int)*p);
    }
    fprintf(stderr, "\n");
}
*/

/* connection_parsecommand:
 * Parse a command from the connection, returning NULL if none is available.
 *
 * POP3 is simple enough that this can be done without a machine-generated
 * lexer and a grammar, though the code in pop3.c is a little bit hairy for
 * commands which take multiple parameters. This might get changed....
 */
struct {
    char *s;
    enum pop3_command_code cmd;
} pop3_commands[] =
    {{"APOP", APOP},
     {"DELE", DELE},
     {"LIST", LIST},
     {"NOOP", NOOP},
     {"PASS", PASS},
     {"QUIT", QUIT},
     {"RETR", RETR},
     {"RSET", RSET},
     {"STAT", STAT},
     {"TOP",  TOP },
     {"UIDL", UIDL},
     {"USER", USER},
     {NULL,   UNKNOWN}}; /* last command MUST have s = NULL */

pop3command connection_parsecommand(connection c) {
    char *p, *q, *r;
    pop3command pc = NULL;

    /* skip initial whitespace */
    for (p = c->buffer; p < c->p && strchr(" \t", *p); ++p);
    if (p == c->p) return NULL;
    
    /* find end of command */
    for (q = p; q < c->p && !strchr("\r\n", *q); ++q);
    if (q == c->p) return NULL;

    if (q >= p) {
        int i;
        size_t n;
        /* identify the command */
        for (i = 0; pop3_commands[i].s; ++i)
            if (!strncasecmp(p, pop3_commands[i].s, n = strlen(pop3_commands[i].s)) && (!*(p + n) || strchr(" \t\r\n", *(p + n)))) {
                char *s = p + n;
                for (; s < q && strchr(" \t", *s); ++s);
                pc = pop3command_new(pop3_commands[i].cmd, s, q);
            }

        if (!pc) pc = pop3command_new(UNKNOWN, NULL, NULL);
    }

    /* now update the buffer */
    for (; q < c->p && strchr("\r\n", *q); ++q);

    memmove(c->buffer, q, c->buffer + c->bufferlen - q);
    c->p = c->buffer;

    return pc;
}

/* connection_sendresponse:
 * Send a +OK... / -ERR... response to a message. Returns 1 on success or 0 on
 * failure.
 */
int connection_sendresponse(connection c, const int success, const char *s) {
    char *x;
    size_t l, m;
    x = (char*)malloc(4 + strlen(s) + 3);
    if (!x) return 0;
    sprintf(x, "%s %s\r\n", success ? "+OK" : "-ERR", s);
    m = write(c->s, x, l = strlen(x));
    free(x);
    return (m == l);
}

/* connection_sendline:
 * Send an arbitrary line to a connected peer. Returns 1 on success or 0 on
 * failure. Used to send multiline responses.
 */
int connection_sendline(connection c, const char *s) {
    char *x;
    size_t l, m;
    x = (char*)malloc(3 + strlen(s));
    if (!x) return 0;
    sprintf(x, "%s\r\n", s);
    m = write(c->s, x, l = strlen(x));
    free(x);
    return (m == l);
}

/* pop3command_new:
 * Create a new pop3command object.
 */
pop3command pop3command_new(const enum pop3_command_code cmd, const char *s1, const char *s2) {
    pop3command p;
    p = (pop3command)malloc(sizeof(struct _pop3command));

    p->cmd = cmd;
    if (s1 && s2 && s2 > s1) {
        p->tail = (char*)malloc(s2 - s1 + 1);
        strncpy(p->tail, s1, s2 - s1);
        *(p->tail + (s2 - s1)) = 0;
    } else p->tail = NULL;

    return p;
}

/* pop3command_delete:
 * Free a command returned by pop3command_new.
 */
void pop3command_delete(pop3command p) {
    if (!p) return;
    if (p->tail) free(p->tail);
    free(p);
}
