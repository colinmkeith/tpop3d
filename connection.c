/*
 * connection.c:
 * deal with connections from clients
 *
 * Copyright (c) 2000 Chris Lightfoot.
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

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>

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

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#include "buffer.h"
#include "connection.h"
#include "listener.h"
#include "util.h"

extern int verbose;

/* make_timestamp:
 * Create a timestamp string. */
#define TIMESTAMP_LEN   32
static char hex[] = "0123456789abcdef";

static char *make_timestamp(const char *domain) {
    int fd;
    unsigned char buffer[TIMESTAMP_LEN / 2], *q;
    struct utsname u;
    char *s, *p;
    size_t l;
    ssize_t n = 0;

    if (!domain) {
        if (uname(&u) == -1) return NULL;
        domain = u.nodename;
    }

    s = xmalloc(l = 1 + TIMESTAMP_LEN + 1 + strlen(domain) + 2);
    if (!s) return NULL;
    memset(s, 0, l);
    *s = '<';
    
    /* Get random "timestamp" data. */
    fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        do
            n = read(fd, buffer, sizeof(buffer));
        while (n == -1 && errno == EINTR);
        close(fd);
    }
        
    if (n != sizeof(buffer)) {
        /* OK, we need to get some pseudo-random data from rand(3).
         * FIXME This is bad from a security PoV, and should be replaced by
         * hashing some rapidly-changing data. */
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
 * Create a connection object from a socket. */
connection connection_new(int s, const struct sockaddr_in *sin, listener L) {
    int n;
    connection c = NULL;

    alloc_struct(_connection, c);

    c->s = s;
    c->sin = *sin;

    n = sizeof(c->sin_local);
    if (getsockname(s, (struct sockaddr*)&(c->sin_local), &n) < 0) {
        log_print(LOG_WARNING, "connection_new: getsockname: %m");
        goto fail;
    }

    c->remote_ip = xstrdup(inet_ntoa(c->sin.sin_addr));
    c->local_ip = xstrdup(inet_ntoa(c->sin_local.sin_addr));

#ifdef MASS_HOSTING
    if (L->have_re)
        c->domain = listener_obtain_domain(L, s);
#endif
    if (!c->domain) {
        if (L->domain)
            c->domain = xstrdup(L->domain);
        else
            c->domain = xstrdup(c->local_ip);
    }

    c->idstr = xmalloc(strlen(c->remote_ip) + 1 + (c->domain ? strlen(c->domain) : 0) + 16);
    if (c->domain) sprintf(c->idstr, "[%d]%s/%s", s, c->remote_ip, c->domain);
    else sprintf(c->idstr, "[%d]%s", s, c->remote_ip);

    /* Read and write buffers */
    c->rdb = buffer_new(1024);
    c->wrb = buffer_new(32768);

    c->timestamp = make_timestamp(c->domain);
    if (!c->timestamp) goto fail;

    /* I/O abstraction layer */
#ifdef USE_TLS
    if (L->tls.mode == immediate) {
        if (!(c->io = (struct ioabs*)ioabs_tls_create(c, L))) {
            log_print(LOG_ERR, _("connection_new: could not set up TLS I/O abstraction layer for `%s'"), c->idstr);
            goto fail;
        }
    } else
#endif
    c->io = (struct ioabs*)ioabs_tcp_create();
    
    c->state = authorisation;

    c->idlesince = time(NULL);
    c->frozenuntil = 0;

    if (!connection_sendresponse(c, 1, c->timestamp)) {
        log_print(LOG_ERR, "connection_new: could not send timestamp to `%s'", c->idstr);
        goto fail;
    }

    c->l = L;

    return c;

fail:
    connection_delete(c);
    return NULL;
}

/* connection_delete:
 * Delete a connection and disconnect the peer. */
void connection_delete(connection c) {
    if (!c) return;

    if (c->s != -1) {
        /* This is a forced shutdown of the underlying socket connection. 
         * Calling code should normally ensure that the connection is properly
         * shut down and that c->s is set to -1 before calling
         * connection_delete. */
        shutdown(c->s, 2);
        close(c->s);
    }

    if (c->a) authcontext_delete(c->a);
    if (c->m) (c->m)->delete(c->m);

    if (c->domain)     xfree(c->domain);
    if (c->remote_ip)  xfree(c->remote_ip);
    if (c->local_ip)   xfree(c->local_ip);
    if (c->idstr)      xfree(c->idstr);
    if (c->rdb)        buffer_delete(c->rdb);
    if (c->wrb)        buffer_delete(c->wrb);
    if (c->io)         c->io->destroy(c);
    if (c->timestamp)  xfree(c->timestamp);
    if (c->user)       xfree(c->user);
    if (c->pass)       xfree(c->pass);
    xfree(c);
}

/* connection_isfrozen CONNECTION
 * Is CONNECTION frozen? */
int connection_isfrozen(connection c) {
    return c->frozenuntil && c->frozenuntil > time(NULL);
}

/* connection_shutdown CONNECTION
 * Immediate or delayed shutdown of CONNECTION. If the connection is frozen or
 * if there are data still to be written, then simply set a flag for later
 * real shutdown. */
int connection_shutdown(connection c) {
    if (connection_isfrozen(c) || buffer_available(c->wrb) > 0) {
        c->do_shutdown = 1;
        return IOABS_WOULDBLOCK;
    } else return c->io->shutdown(c);
}

/* connection_send_now CONNECTION DATA COUNT
 * Send COUNT bytes of DATA to CONNECTION immediately, if possible. Returns
 * the number of bytes written on success, IOABS_WOULDBLOCK if the write would
 * block, or IOABS_ERROR on error. Does not interact with the write buffer at
 * all, and must be called only when it is empty. */
static ssize_t connection_send_now(connection c, const char *data, const size_t len) {
    if (!c->io->immediate_write || connection_isfrozen(c))
        return 0;
    return c->io->immediate_write(c, data, len);
}

/* connection_send CONNECTION DATA COUNT
 * Send COUNT bytes of DATA to CONNECTION, either immediately if possible or
 * inserting it into the buffer otherwise. Returns 1 on success or 0 on
 * failure. */
ssize_t connection_send(connection c, const char *data, const size_t l) {
    size_t len;
    ssize_t n;
    len = l;
    if (buffer_available(c->wrb) == 0) {
        n = connection_send_now(c, data, len);
        if (n == len) return 1;
        else if (n == IOABS_ERROR) return 0;
        else if (n > 0) {
            data += n;
            len -= n;
        } /* else IOABS_WOULDBLOCK */
    }

    if (len > 0)
        buffer_push_data(c->wrb, data, len);
        /* XXX should try a write from the buffer now...? */
    return 1;
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

/* connection_freeze:
 * Mark a connection as frozen. */
void connection_freeze(connection c) {
    c->frozenuntil = time(NULL) + 3;
}

/* pop3_commands:
 * Commands the server supports. */
struct {
    char *s;
    enum pop3_command_code cmd;
} pop3_commands[] =
    {{"APOP", APOP},
     {"CAPA", CAPA},
     {"DELE", DELE},
     {"LIST", LIST},
     {"NOOP", NOOP},
     {"PASS", PASS},
     {"QUIT", QUIT},
     {"RETR", RETR},
     {"RSET", RSET},
     {"STAT", STAT},
     {"STLS", STLS},
     {"TOP",  TOP },
     {"UIDL", UIDL},
     {"USER", USER},
     {"LAST", LAST},
     {NULL,   UNKNOWN}}; /* last command MUST have s = NULL */

/* connection_parsecommand CONNECTION
 * Parse a command from CONNECTION, returning NULL if none is available. */
pop3command connection_parsecommand(connection c) {
    static char *line; /* static buffer so we don't spend all day reallocating things... */
    static size_t llen;
    size_t i;
    char *p;
    pop3command pc = NULL;

    /* Some clients send \r\n, some send \n, others send a mixture. In the
     * latter case we must be careful not to interpret command1\ncommand2\r\n
     * as a single command. So always use \n as the line ending and strip off
     * any trailing \r. */
    if (!(p = buffer_consume_to_mark(c->rdb, "\n", line, &llen)))
        return NULL;
    else
        line = p;

    /* remove trailing eol */
    for (i = llen - 1; i > 0 && strchr("\r\n", line[i]); --i)
        line[i] = 0;
    p = line + strspn(line, " \t"); /* skip leading whitespace */
    
    if (verbose) {
        if  (strncasecmp(p, "PASS", 4))
            log_print(LOG_DEBUG, "connection_parsecommand: client %s: received `%s'", c->idstr, p);
        else
            log_print(LOG_DEBUG, "connection_parsecommand: client %s: received `%.4s [...]'", c->idstr, p);
    }

    pc = pop3command_new(p);

    return pc;
}

/* pop3command_new:
 * Create a new pop3command object. */
pop3command pop3command_new(const char *s) {
    pop3command p;
    const char *q;
    int i;
    
    alloc_struct(_pop3command, p);

    /* Ugly. PASS is a special case, because we permit a password to contain
     * spaces. */
    q = s + strspn(s, " \t");
    if (strncasecmp(q, "PASS ", 5) == 0) {
        /* Manual parsing. */
        p->cmd = PASS;
        p->toks = xcalloc(sizeof *p->toks, 1);
        
        p->toks->str = xstrdup(q);
        chomp(p->toks->str);
        p->toks->str[4] = 0;
        
        p->toks->toks = xcalloc(sizeof(char*), 2);
        p->toks->toks[0] = p->toks->str;
        p->toks->toks[1] = p->toks->str + 5;
        
        p->toks->num = 2;

        return p;
    }

    p->cmd = UNKNOWN;
    p->toks = tokens_new(s, " \t");

    /* Does this command have a sane structure? */
    if (p->toks->num < 1 || p->toks->num > 3)
        return p;

    /* Try to identify the command. */
    for (i = 0; pop3_commands[i].s; ++i)
        if (!strcasecmp((char*)(p->toks->toks[0]), pop3_commands[i].s)) {
            p->cmd = pop3_commands[i].cmd;
            break;
        }

    return p;
}

/* pop3command_delete:
 * Free a command returned by pop3command_new. */
void pop3command_delete(pop3command p) {
    if (!p) return;
    if (p->toks) tokens_delete(p->toks);
    xfree(p);
}

/* connection_sendresponse:
 * Send a +OK... / -ERR... response to a message. Returns 1 on success or 0 on
 * failure. */
int connection_sendresponse(connection c, const int success, const char *s) {
    /*
     * For efficiency's sake, we should send this bit-by-bit, avoiding another
     * buffer copy. But unfortunately, there are POP3 clients in the world
     * so stupid that they assume a whole response will arrive in a single TCP
     * segment. Particular examples include POP3 virus-scanning proxies, such
     * as Norman ASA's, which was evidently written by somebody very lazy.
     * 
     * Obviously there's no way to guarantee how the packets in a TCP stream
     * are disposed, in general, but we can increase the probability of success
     * by trying to ensure here that our response is contained in a single
     * write call. It still might get split up by the ioabs layer, but we have
     * to take our chances....
     */
    static char *buf;
    static size_t buflen;
    size_t l;
    
    l = (success ? 6 : 7) + strlen(s);

    if (!buf || buflen < l + 1)
        buf = xrealloc(buf, buflen = l + 1);
    
    sprintf(buf, "%s %s\r\n", success ? "+OK" : "-ERR", s);
    if (connection_send(c, buf, l)) {
        if (verbose)
            log_print(LOG_DEBUG, _("connection_sendresponse: client %s: sent `%s %s'"), c->idstr, success ? "+OK" : "-ERR", s);
        return 1;
    } else
        return 0;
}

/* connection_sendline:
 * Send an arbitrary line to a connected peer. Returns 1 on success or 0 on
 * failure. Used to send multiline responses. */
int connection_sendline(connection c, const char *s) {
    /* Buffer copy, for reasons as given in connection_sendresponse. */
    static char *buf;
    static size_t buflen;
    size_t l;
    
    l = strlen(s) + 2;
    
    if (!buf || buflen < l + 1)
        buf = xrealloc(buf, buflen = l + 1);

    sprintf(buf, "%s\r\n", s);
    return connection_send(c, buf, l);
}

/* connection_sendmessage:
 * Send to the connected peer a +OK response followed by the header and up to n
 * lines of the body of a message which begins at offset msgoffset + skip in
 * the file referenced by fd, which is assumed to be a mappable object. Lines
 * which begin . are escaped as required by RFC1939, and each line is
 * terminated with `\r\n'. If n is -1, the whole message is sent.
 *
 * RFC1939 doesn't define what a server which encounters an error half-way
 * through sending a message should do. In any case it's clear that we mustn't
 * send the final ., since that would result in the user obtaining a truncated
 * message.  So we return -1 if the message could not be sent but a -ERR
 * response was transmitted to the client, -2 if sending failed after a +OK
 * response was sent, or the number of bytes written on success.
 *
 * Assumes the message on disk uses only `\n' to indicate EOL. */
int connection_sendmessage(connection c, int fd, size_t msgoffset, size_t skip, size_t msglength, int n) {
    char *filemem;
    char *p, *q, *r;
    size_t length, offset;
    ssize_t nwritten = 0;
    /* Doing lots of small writes is bad for performance, so buffer here and
     * only write data when we've accumulated a large chunk of data. Use our
     * own buffer here, rather than the connection IO buffer, since we don't
     * want to use as much memory as a single message. */
    static char *buffer;
    static size_t buflen;
    char *bufptr, *msg = NULL;

    if (!buffer) buffer = xmalloc(buflen = 32768);
    bufptr = buffer;

#define buffer_push(sa, na) \
        do { \
            char *s; \
            size_t n; \
            s = sa; \
            n = na; \
            /* Unlikely but must deal with this case. */ \
            if (n > buflen) { \
                if (bufptr > buffer && !connection_send(c, buffer, bufptr - buffer)) \
                    goto write_failure; \
                bufptr = buffer; \
                if (!connection_send(c, s, n)) \
                    goto write_failure; \
            } else { \
                if ((bufptr + n) > (buffer + buflen)) { \
                    if (!connection_send(c, buffer, bufptr - buffer)) \
                        goto write_failure; \
                    bufptr = buffer; \
                } \
                memcpy(bufptr, s, n); \
                bufptr += n; \
            } \
            nwritten += n; \
        } while (0)

    offset = msgoffset - (msgoffset % PAGESIZE);
    length = (msgoffset + msglength + PAGESIZE) ;
    length -= length % PAGESIZE;

    filemem = mmap(0, length, PROT_READ, MAP_PRIVATE, fd, offset);
    if (filemem == MAP_FAILED) {
        log_print(LOG_ERR, "connection_sendmessage: mmap: %m");
        connection_sendresponse(c, 0, _("Cannot send message"));
        return -1; /* Failure before +OK sent. */
    }

    msg = _("+OK Message follows\r\n");
    buffer_push(msg, strlen(msg));

    /* Find the beginning of the message headers */
    p = filemem + (msgoffset % PAGESIZE);
    r = p + msglength;
    p += skip;

    /* Send the message headers */
    while (p < r && *p != '\n') {
        q = memchr(p, '\n', r - p);
        if (!q) q = r;
        errno = 0;
        
        /* Escape a leading ., if present. */
        if (*p == '.')
            buffer_push(".", 1);
        
        /* Send line itself. */
        buffer_push(p, q - p);
        buffer_push("\r\n", 2);

        p = q + 1;
    }

    ++p;

    errno = 0;
    buffer_push("\r\n", 2);
    
    /* Now send the message itself */
    while (p < r && n) {
        if (n > 0) --n;

        q = memchr(p, '\n', r - p);
        if (!q) q = r;
        errno = 0;

        /* Escape a leading ., if present. */
        if (*p == '.')
            buffer_push(".", 1);
        
        /* Send line itself. */
        buffer_push(p, q - p);
        buffer_push("\r\n", 2);

        p = q + 1;
    }

    /* Finish up. */
    buffer_push(".\r\n", 3);

    if (bufptr > buffer && !connection_send(c, buffer, bufptr - buffer))
        goto write_failure;
    
    if (munmap(filemem, length) == -1)
        log_print(LOG_ERR, "connection_sendmessage: munmap: %m");
    
    errno = 0;

    return nwritten + 3;

#undef buffer_push
    
write_failure:
    log_print(LOG_ERR, _("connection_sendmessage: send failure"));
    munmap(filemem, length);
    return -2;
}

