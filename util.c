/*
 * util.c:
 * Various utility functions for tpop3d.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/mman.h>

#include "errprintf.h"
#include "util.h"

/* print_log:
 * Because many systems do not have LOG_PERROR, we use a custom function to
 * write an error to the system log, and optionally to standard error as
 * well.
 */
extern int log_stderr;      /* in main.c */

void print_log(int priority, const char *fmt, ...) {
    char *s;
    va_list ap;
    va_start(ap, fmt);
    s = verrprintf(fmt, ap);
    va_end(ap);
    syslog(priority, "%s", s);
    if (log_stderr) fprintf(stderr, "%s\n", s);
    free(s);
}

/* xwrite:
 * Write some data, taking account of short writes.
 */
ssize_t xwrite(int fd, const void *buf, size_t count) {
    size_t c = count;
    const char *b = (const char*)buf;
    while (c > 0) {
        int e = write(fd, b, count);
        if (e > 0) {
            c -= e;
            b += e;
        } else return e;
    } while (c > 0);
    return count;
}

/* daemon:
 * Become a daemon. From "The Unix Programming FAQ", Andrew Gierth et al.
 */
int daemon(int nochdir, int noclose) {
    switch (fork()) {
        case 0:  break;
        case -1: return -1;
        default: _exit(0);          /* exit the original process */
    }

    if (setsid() < 0)               /* shouldn't fail */
        return -1;

    switch (fork()) {
        case 0:  break;
        case -1: return -1;
        default: _exit(0);
    }

    if (!nochdir) chdir("/");

    if (!noclose) {
        int i, j = sysconf(_SC_OPEN_MAX); /* getdtablesize()? */
        for (i = 0; i < j; ++i) close(i);
        open("/dev/null",O_RDWR);
        dup(0); dup(0);
    }

    return 0;
}

#ifdef __SVR4
/* inet_aton:
 * Implementation of inet_aton for machines (Solaris [cough]) which do not
 * have it.
 */
int inet_aton(const char *s, struct in_addr *ip) {                              
    in_addr_t i = inet_addr(s);                                                 
    if (i == ((in_addr_t)-1)) return 0;                                         
    memcpy(ip, &i, sizeof(int));                                                
    return 1;                                                                   
}                                                                               
#endif

/* write_file:
 * Send to socket sck the header and up to n lines of the body of a message
 * which begins at offset msgoffset + skip in the file referenced by fd, which
 * is assumed to be a mappable object. Lines which begin . are escaped as
 * required by RFC1939, and each line is terminated with `\r\n'. If n is -1,
 * the whole message is sent. Returns 1 on success or 0 on failure.
 *
 * XXX Assumes that the message on disk uses only '\n' to indicate EOL.
 */
int write_file(int fd, int sck, size_t msgoffset, size_t skip, size_t msglength, int n) {
    char *filemem;
    char *p, *q, *r;
    size_t length, offset;
    
    offset = msgoffset - (msgoffset % PAGESIZE);
    length = (msgoffset + msglength + PAGESIZE) ;
    length -= length % PAGESIZE;

    filemem = mmap(0, length, PROT_READ, MAP_PRIVATE, fd, offset);
    if (filemem == MAP_FAILED) {
        print_log(LOG_ERR, "write_file: mmap: %m");
        return 0;
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
        if (*p == '.' && !try_write(sck, ".", 1)) goto write_failure;
        /* Send line itself. */
        if (!try_write(sck, p, q - p) || !try_write(sck, "\r\n", 2))
            goto write_failure;
        p = q + 1;
    } while (*p != '\n');
    ++p;

    errno = 0;
    if (!try_write(sck, "\r\n", 2)) {
        print_log(LOG_ERR, "write_file: write: %m");
        munmap(filemem, length);
        return 0;
    }
    
    /* Now send the message itself */
    while (p < r && n) {
        if (n > 0) --n;

        q = memchr(p, '\n', r - p);
        if (!q) q = r;
        errno = 0;

        /* Escape a leading ., if present. */
        if (*p == '.' && !try_write(sck, ".", 1)) goto write_failure;
        /* Send line itself. */
        if (!try_write(sck, p, q - p) || !try_write(sck, "\r\n", 2))
            goto write_failure;

        p = q + 1;
    }
    if (munmap(filemem, length) == -1)
        print_log(LOG_ERR, "write_file: munmap: %m");
    
    errno = 0;
    if (!try_write(sck, ".\r\n", 3)) {
        print_log(LOG_ERR, "write_file: write: %m");
        return 0;
    } else return 1;

write_failure:
    print_log(LOG_ERR, "write_file: write: %m");
    munmap(filemem, length);
    return 0;
}

/* parse_uid:
 * Get a user id from a user name or number. Sets u and returns 1 on success,
 * or returns 0 on failure.
 */
int parse_uid(const char *user, uid_t *u) {
    char *v;
    long l;
    
    /* Numeric user id? */
    l = strtol(user, &v, 10);
    if (v && !*v) {
        *u = (uid_t)l;
        return 1;
    } else {
        struct passwd *pw = getpwnam(user);
        if (pw) {
            *u = pw->pw_uid;
            return 1;
        }
    }

    return 0;
}

/* parse_gid:
 * Get a group id from a group name or number. Sets g and returns 1 on
 * success, or returns 0 on failure.
 */
gid_t parse_gid(const char *group, gid_t *g) {
    char *v;
    long l;
    /* Numeric group id? */
    l = strtol(group, &v, 10);
    if (v && !*v) {
        *g = (gid_t)l;
        return 1;
    } else {
        struct group *grp = getgrnam(group);
        if (grp) {
            *g = grp->gr_gid;
            return 1;
        }
    }

    return 0;
}
