/*
 * connection.c:
 * deal with connections from clients
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif // HAVE_CONFIG_H

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "connection.h"
#include "util.h"

extern int verbose;

/* make_timestamp:
 * Create a timestamp string.
 */
#define TIMESTAMP_LEN   32
static char hex[] = "0123456789abcdef";

static char *make_timestamp(const char *domain) {
    int fd;
    unsigned char buffer[TIMESTAMP_LEN / 2], *q;
    struct utsname u;
    char *s, *p;
    size_t l;

    if (!domain) {
        if (uname(&u) == -1) return NULL;
        domain = u.nodename;
    }

    s = (char*)malloc(l = 1 + TIMESTAMP_LEN + 1 + strlen(domain) + 2);
    if (!s) return NULL;
    memset(s, 0, l);
    *s = '<';
    
    /* Get random "timestamp" data. */
    fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        if (read(fd, buffer, sizeof(buffer)) != sizeof(buffer)) {
            free(s);
            return NULL;
        }
        close(fd);
    } else {
        /* OK, we need to get some pseudo-random data from rand(3).
         * FIXME This is bad from a security PoV, and should be replaced by
         * hashing some rapidly-changing data.
         */
        unsigned char *p;
        for (p = buffer; p < buffer + sizeof(buffer); ++p)
            *p = (unsigned char)(rand() & 0xff);
    }
    
    for (p = s + 1, q = buffer; q < buffer + sizeof(buffer); ++q) {
        *p++ = hex[(((int)*q) >> 4) & 0x0f];
        *p++ = hex[((int)*q) & 0x0f];
    }
    strcat(s, "@");
    strcat(s, domain);
    strcat(s, ">");

    return s;
}

/* connection_new:
 * Create a connection object from a socket.
 */
connection connection_new(int s, const struct sockaddr_in *sin, const char *domain) {
    connection c = 0;
    c = (connection)malloc(sizeof(struct _connection));
    if (!c) return NULL;

    memset(c, 0, sizeof(struct _connection));

    c->s = s;
    memcpy(&(c->sin), sin, sizeof(struct sockaddr_in));

    if (domain) c->domain = strdup(domain);

    c->idstr = (char*)malloc(strlen(inet_ntoa(sin->sin_addr)) + 1 + (domain ? strlen(domain) : 0) + 16);
    if (domain) sprintf(c->idstr, "[%d]%s/%s", s, inet_ntoa(sin->sin_addr), domain);
    else sprintf(c->idstr, "[%d]%s", s, inet_ntoa(sin->sin_addr));

    c->p = c->buffer = (char*)malloc(c->bufferlen = MAX_POP3_LINE);
    if (!c->buffer) goto fail;

    c->timestamp = make_timestamp(c->domain);
    if (!c->timestamp) goto fail;
    
    c->state = authorisation;

    c->idlesince = time(NULL);

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
    close(c->s);

    if (c->a) authcontext_delete(c->a);
    if (c->m) mailspool_delete(c->m);

    if (c->domain)    free(c->domain);
    if (c->idstr)     free(c->idstr);
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
    if (!c) return -1;
    if (c->p == c->buffer + c->bufferlen) {
        print_log(LOG_ERR, "connection_read: client %s: over-long line", c->idstr);
        errno = ENOBUFS;
        return -1;
    }
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
     {"LAST", LAST},
     {NULL,   UNKNOWN}}; /* last command MUST have s = NULL */

pop3command connection_parsecommand(connection c) {
    char *p, *q;
    pop3command pc = NULL;

    /* Skip initial whitespace. */
    for (p = c->buffer; p < c->p && strchr(" \t", *p); ++p);
    if (p == c->p) return NULL;
    
    /* Find end of command. */
    for (q = p; q < c->p && !strchr("\r\n", *q); ++q);
    if (q == c->p) return NULL;

    /* Replace trailing newlines with NULs. */
    for (; q < c->p && strchr("\r\n", *q); ++q) *q = 0;

    pc = pop3command_new(p);

    if (verbose) {
        char *s;
        int i, l;
        l = sizeof("connection_parsecommand: client : received `'") + strlen(c->idstr);
        for (i = 0; i < pc->toks->toks->n_used; ++i) l += strlen((char*)(pc->toks->toks->ary[i].v)) + 6;
        s = (char*)malloc(l);
        sprintf(s, "connection_parsecommand: client %s: received `", c->idstr);
        for (i = 0; i < pc->toks->toks->n_used; ++i) {
            if (i == 0 || pc->cmd != PASS) strcat(s, (char*)(pc->toks->toks->ary[i].v));
            else strcat(s, "[...]");
            if (i != pc->toks->toks->n_used - 1) strcat(s, " ");
        }
        strcat(s, "'");
        print_log(LOG_DEBUG, "%s", s);
        free(s);
    }
                
    /* now update the buffer */
    memmove(c->buffer, q, c->buffer + c->bufferlen - q);
    c->p = c->buffer;

    return pc;
}

/* pop3command_new:
 * Create a new pop3command object.
 */
pop3command pop3command_new(const char *s) {
    pop3command p;
    int i;
    
    p = (pop3command)malloc(sizeof(struct _pop3command));

    p->cmd = UNKNOWN;
    p->toks = tokens_new(s, " \t");

    /* Does this command have a sane structure? */
    if (p->toks->toks->n_used < 1 || p->toks->toks->n_used > 3)
        return p;

    /* Try to identify the command. */
    for (i = 0; pop3_commands[i].s; ++i)
        if (!strcasecmp((char*)(p->toks->toks->ary[0].v), pop3_commands[i].s)) {
            p->cmd = pop3_commands[i].cmd;
            break;
        }

    return p;
}

/* pop3command_delete:
 * Free a command returned by pop3command_new.
 */
void pop3command_delete(pop3command p) {
    if (!p) return;
    if (p->toks) tokens_delete(p->toks);
    free(p);
}

/* connection_sendresponse:
 * Send a +OK... / -ERR... response to a message. Returns 1 on success or 0 on
 * failure.
 */
int connection_sendresponse(connection c, const int success, const char *s) {
    char *x;
    size_t l, m;
    x = (char*)malloc(l = (4 + strlen(s) + 3 + 1));
    if (!x) return 0;
    snprintf(x, l, "%s %s\r\n", success ? "+OK" : "-ERR", s);
    m = xwrite(c->s, x, l = strlen(x));
    free(x);
    if (verbose)
        print_log(LOG_DEBUG, "connection_sendresponse: client %s: sent `%s %s'", c->idstr, success? "+OK" : "-ERR", s);
    return (m == l);
}

/* connection_sendline:
 * Send an arbitrary line to a connected peer. Returns 1 on success or 0 on
 * failure. Used to send multiline responses.
 */
int connection_sendline(connection c, const char *s) {
    char *x;
    size_t l, m;
    x = (char*)malloc(l = (3 + strlen(s)));
    if (!x) return 0;
    snprintf(x, l, "%s\r\n", s);
    m = xwrite(c->s, x, l = strlen(x));
    free(x);
    return (m == l);
}


