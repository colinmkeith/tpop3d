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

#include "connection.h"
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
connection connection_new(int s, const struct sockaddr_in *sin, const char *domain) {
    int n;
    connection c = NULL;

    c = xcalloc(1, sizeof *c);

    c->s = s;
    memcpy(&(c->sin), sin, sizeof(struct sockaddr_in));

    n = sizeof(c->sin_local);
    if (getsockname(s, (struct sockaddr *)&(c->sin_local), &n) < 0) {
      log_print(LOG_WARNING, _("connection_new: getsockname error %d"), errno);
      goto fail;
    }

    c->remote_ip = xstrdup(inet_ntoa(c->sin.sin_addr));
    c->local_ip = xstrdup(inet_ntoa(c->sin_local.sin_addr));

    if (domain) c->domain = xstrdup(domain);

    if (!c->domain)
      c->domain = xstrdup(c->local_ip);

    c->idstr = xmalloc(strlen(c->remote_ip) + 1 + (c->domain ? strlen(c->domain) : 0) + 16);
    if (c->domain) sprintf(c->idstr, "[%d]%s/%s", s, c->remote_ip, c->domain);
    else sprintf(c->idstr, "[%d]%s", s, c->remote_ip);

    /* read and write buffers */
    c->rdb.p = c->rdb.buffer = xmalloc(c->rdb.bufferlen = MAX_POP3_LINE);
    if (!c->rdb.buffer) goto fail;

    c->wrb.p = c->wrb.buffer = xmalloc(c->wrb.bufferlen = MAX_POP3_LINE);
    if (!c->wrb.buffer) goto fail;

    c->timestamp = make_timestamp(c->domain);
    if (!c->timestamp) goto fail;
    
    c->state = authorisation;

    c->idlesince = time(NULL);
    c->frozenuntil = 0;

    if (!connection_sendresponse(c, 1, c->timestamp)) {
        log_print(LOG_ERR, "connection_new: could not send timestamp to `%s'", c->idstr);
        goto fail;
    }

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
        shutdown(c->s, 2);
        close(c->s);
    }

    if (c->a) authcontext_delete(c->a);
    if (c->m) (c->m)->delete(c->m);

    if (c->domain)     xfree(c->domain);
    if (c->remote_ip)  xfree(c->remote_ip);
    if (c->local_ip)   xfree(c->local_ip);
    if (c->idstr)      xfree(c->idstr);
    if (c->rdb.buffer) xfree(c->rdb.buffer);
    if (c->wrb.buffer) xfree(c->wrb.buffer);
    if (c->timestamp)  xfree(c->timestamp);
    if (c->user)       xfree(c->user);
    if (c->pass)       xfree(c->pass);
    xfree(c);
}

/* connection_read:
 * Read data from the socket into the buffer, if available. Returns -1 on
 * error or if the read would block (in this case errno is set to EAGAIN)
 * or if the buffer is full; or 0 on EOF or the number of bytes read. */
ssize_t connection_read(connection c) {
    ssize_t n;
    if (!c) return -1;
    if (c->rdb.p == c->rdb.buffer + c->rdb.bufferlen) {
        log_print(LOG_ERR, _("connection_read: client %s: over-long line"), c->idstr);
        errno = ENOBUFS;
        return -1;
    }
    do {
        n = read(c->s, c->rdb.p, c->rdb.buffer + c->rdb.bufferlen - c->rdb.p);
    } while (n == -1 && errno == EINTR);
    if (n > 0) {
        c->rdb.p += n;
        c->nrd += n;    /* Keep track of data transferred. */
    }
    return n;   /* if a read would block, return -1 with errno == EAGAIN */
}

#define WRCHUNK     1024    /* the size of chunk in which we write things */

/* connection_write:
 * Send pending data, if any, to the client. Returns -1 on error or if the
 * write would block, in which case errno is set to EAGAIN, or the number of
 * bytes written, which may be 0 if the write buffer is empty. */
ssize_t connection_write(connection c) {
    char *d;
    ssize_t n, ntotal = 0;
    if (c->frozenuntil > time(NULL)) return 0;
    for (d = c->wrb.buffer; d < c->wrb.p; d += n) {
        size_t len = WRCHUNK;
        if (d + WRCHUNK >= c->wrb.p)
            len = c->wrb.p - d;
        do {
            n = write(c->s, d, len);
        } while (n == -1 && errno == EINTR);
        if (n == -1) break;
        else ntotal += n;
    }
    if (ntotal > 0) {
        c->nwr += ntotal;
        memmove(c->wrb.buffer, c->wrb.buffer + ntotal, c->wrb.p - (c->wrb.buffer + ntotal));
        c->wrb.p -= ntotal;
    }
    return ntotal;
}

/* connection_send_now:
 * Send the given data to the client immediately, if possible. Returns the
 * number of bytes written on success, or -1 on error or if the write would
 * block. Does not interact with the write buffer at all. */
static ssize_t connection_send_now(connection c, const char *data, const size_t len) {
    ssize_t n;
    if (c->frozenuntil > time(NULL)) return 0;
    do {
        n = write(c->s, data, len);
    } while (n == -1 && errno == EINTR);
    if (n > 0) c->nwr += n;
    return n;
}

/* connection_send:
 * Send some data to the client, either immediately if possible or inserting it
 * into the buffer otherwise. Returns 1 on success or 0 on failure. */
ssize_t connection_send(connection c, const char *data, const size_t l) {
    size_t len;
    ssize_t n;
    len = l;
    if (c->wrb.p == c->wrb.buffer) {
        /* Buffer is empty. Try sending the data now. */
        n = connection_send_now(c, data, len);
        if (n == len) return 1;
        else if (n == -1 && errno != EAGAIN) return 0;
        else if (n > 0) {
            data += n;
            len -= n;
        }
    }
    /* Append remaining data to end of buffer. */
    while (c->wrb.p + len > c->wrb.buffer + c->wrb.bufferlen) {
        /* Expand buffer. */
        int d;
        d = c->wrb.p - c->wrb.buffer;
        c->wrb.buffer = xrealloc(c->wrb.buffer, c->wrb.bufferlen *= 2);
        c->wrb.p = c->wrb.buffer + d; 
    }
    memcpy(c->wrb.p, data, len);
    c->wrb.p += len;

    /* Try a send immediately. */
    if (connection_write(c) == -1 && errno != EAGAIN)
        return 0;
    else return 1;
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

/* connection_parsecommand:
 * Parse a command from the connection, returning NULL if none is available. */
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
    for (p = c->rdb.buffer; p < c->rdb.p && strchr(" \t", *p); ++p);
    if (p == c->rdb.p) return NULL;
    
    /* Find end of command. */
    for (q = p; q < c->rdb.p && !strchr("\r\n", *q); ++q);
    if (q == c->rdb.p) return NULL;

    /* Replace trailing newlines with NULs. */
    for (; q < c->rdb.p && strchr("\r\n", *q); ++q) *q = 0;

    pc = pop3command_new(p);

    if (verbose) {
        char *s;
        int i, l;
        l = strlen(_("connection_parsecommand: client %s: received `")) + 2 + strlen(c->idstr);
        for (i = 0; i < pc->toks->num; ++i) l += strlen((char*)(pc->toks->toks[i])) + 6;
        s = xmalloc(l);
        sprintf(s, _("connection_parsecommand: client %s: received `"), c->idstr);
        for (i = 0; i < pc->toks->num; ++i) {
            if (i == 0 || pc->cmd != PASS) strcat(s, (char*)(pc->toks->toks[i]));
            else strcat(s, "[...]");
            if (i != pc->toks->num - 1) strcat(s, " ");
        }
        strcat(s, "'");
        log_print(LOG_DEBUG, "%s", s);
        xfree(s);
    }

    /* now update the buffer */
    memmove(c->rdb.buffer, q, c->rdb.buffer + c->rdb.bufferlen - q);
    c->rdb.p -= q - c->rdb.buffer;

    return pc;
}

/* pop3command_new:
 * Create a new pop3command object. */
pop3command pop3command_new(const char *s) {
    pop3command p;
    const char *q;
    int i;
    
    p = xcalloc(sizeof *p, 1);

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
    if (connection_send(c, success ? "+OK " : "-ERR ", success ? 4 : 5)
            && connection_send(c, s, strlen(s))
            && connection_send(c, "\r\n", 2)) {
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
    return connection_send(c, s, strlen(s)) && connection_send(c, "\r\n", 2);
}

/* connection_sendmessage:
 * Send to the connected peer the header and up to n lines of the body of a
 * message which begins at offset msgoffset + skip in the file referenced by
 * fd, which is assumed to be a mappable object. Lines which begin . are
 * escaped as required by RFC1939, and each line is terminated with `\r\n'. If
 * n is -1, the whole message is sent. Returns the number of bytes written on
 * success or -1 on failure. Assumes the message on disk uses only `\n' to
 * indicate EOL. */
int connection_sendmessage(connection c, int fd, size_t msgoffset, size_t skip, size_t msglength, int n) {
    char *filemem;
    char *p, *q, *r;
    size_t length, offset;
    ssize_t nwritten = 0;
    
    offset = msgoffset - (msgoffset % PAGESIZE);
    length = (msgoffset + msglength + PAGESIZE) ;
    length -= length % PAGESIZE;

    filemem = mmap(0, length, PROT_READ, MAP_PRIVATE, fd, offset);
    if (filemem == MAP_FAILED) {
        log_print(LOG_ERR, "connection_sendmessage: mmap: %m");
        return -1;
    }

    /* Find the beginning of the message headers */
    p = filemem + (msgoffset % PAGESIZE);
    r = p + msglength;
    p += skip;

    /* Send the message headers */
    do {
        q = memchr(p, '\n', r - p);
        if (!q) q = r;
        errno = 0;
        
        /* Escape a leading ., if present. */
        if (*p == '.' && !connection_send(c, ".", 1))
            goto write_failure;
        ++nwritten;
        
        /* Send line itself. */
        if (!connection_send(c, p, q - p) || !connection_send(c, "\r\n", 2))
            goto write_failure;
        nwritten += q - p + 2;

        p = q + 1;
    } while (p < r && *p != '\n');

    ++p;

    errno = 0;
    if (!connection_send(c, "\r\n", 2)) {
        log_print(LOG_ERR, "connection_sendmessage: send: %m");
        munmap(filemem, length);
        return -1;
    }
    
    /* Now send the message itself */
    while (p < r && n) {
        if (n > 0) --n;

        q = memchr(p, '\n', r - p);
        if (!q) q = r;
        errno = 0;

        /* Escape a leading ., if present. */
        if (*p == '.' && !connection_send(c, ".", 1))
            goto write_failure;
        ++nwritten;
        
        /* Send line itself. */
        if (!connection_send(c, p, q - p) || !connection_send(c, "\r\n", 2))
            goto write_failure;
        nwritten += q - p + 2;

        p = q + 1;
    }
    if (munmap(filemem, length) == -1)
        log_print(LOG_ERR, "connection_sendmessage: munmap: %m");
    
    errno = 0;
    if (!connection_send(c, ".\r\n", 3)) {
        log_print(LOG_ERR, "connection_sendmessage: send: %m");
        return -1;
    } else return nwritten + 3;

write_failure:
    log_print(LOG_ERR, "connection_sendmessage: send: %m");
    munmap(filemem, length);
    return -1;
}

