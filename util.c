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
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/mman.h>

#include "md5.h"
#include "util.h"

/* xwrite FD DATA COUNT
 * Write some data, taking account of short writes and signals. */
ssize_t xwrite(int fd, const void *buf, size_t count) {
    size_t c = count;
    const char *b = (const char*)buf;
    while (c > 0) {
        int e;
        e = write(fd, b, c);
        if (e >= 0) {
            c -= e;
            b += e;
        } else if (errno != EINTR) return e;
    }
    return count;
}

/* daemon:
 * Become a daemon. From `The Unix Programming FAQ', Andrew Gierth et al. */
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

#ifndef HAVE_INET_ATON
/* inet_aton:
 * Implementation of inet_aton for machines (Solaris [cough]) which do not
 * have it. */
int inet_aton(const char *s, struct in_addr *ip) {                              
    in_addr_t i = inet_addr(s);                                                 
    if (i == ((in_addr_t)-1)) return 0;                                         
    memcpy(ip, &i, sizeof(int));                                                
    return 1;                                                                   
}                                                                               
#endif /* !HAVE_INET_ATON */

/* parse_uid:
 * Get a user id from a user name or number. Sets u and returns 1 on success,
 * or returns 0 on failure. */
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

/* xsignal NUMBER HANDLER
 * Set a signal with a similar interface to signal(2) using sigaction(2). */
void (*xsignal(int signum, void(*handler)(int)))(int) {
    struct sigaction sa = {0}, sa_old;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handler;
    sa.sa_flags = SA_RESTART;
    if (sigaction(signum, &sa, &sa_old) == -1)
        return SIG_ERR;
    else
        return sa_old.sa_handler;
}

/* parse_gid:
 * Get a group id from a group name or number. Sets g and returns 1 on
 * success, or returns 0 on failure. */
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

/* hex_digest:
 * Make a hex version of a digest. */
char *hex_digest(const unsigned char *u) {
    static char hex[33] = {0};
    const unsigned char *p;
    char *q;
    for (p = u, q = hex; p < u + 16; ++p, q += 2)
        snprintf(q, 3, "%02x", (unsigned int)*p);

    return hex;
}

/* unhex_digest:
 * Turn a hex representation of a digest into binary data. Returns 1 on
 * success or 0 on failure. */
int unhex_digest(const char *from, unsigned char *to) {
    const char *p;
    unsigned char *q;
    for (p = from, q = to; *p && q < to + 16; ++q) {
        *q = 0;
        if (strchr("0123456789", *p))  *q |= ((unsigned int)*p - '0') << 4;
        else if (strchr("abcdef", *p)) *q |= ((unsigned int)*p - 'a' + 10) << 4;
        else if (strchr("ABCDEF", *p)) *q |= ((unsigned int)*p - 'A' + 10) << 4;
        else return 0;
        ++p;
        if (strchr("0123456789", *p))  *q |= ((unsigned int)*p - '0');
        else if (strchr("abcdef", *p)) *q |= ((unsigned int)*p - 'a' + 10);
        else if (strchr("ABCDEF", *p)) *q |= ((unsigned int)*p - 'A' + 10);
        else return 0;
        ++p;
    }

    return 1;
}

#ifndef MTRACE_DEBUGGING
/* xmalloc COUNT
 * Malloc, and abort if malloc fails. */
void *xmalloc(size_t n) {
    void *v;
    v = malloc(n);
    if (!v) abort();
    return v;
}

/* xcalloc NITEMS COUNT
 * As above. */
void *xcalloc(size_t n, size_t m) {
    void *v;
    v = calloc(n, m);
    if (!v) abort();
    return v;
}

/* xrealloc PTR COUNT
 * As above. */
void *xrealloc(void *w, size_t n) {
    void *v;
    v = realloc(w, n);
    if (n != 0 && !v) abort();
    return v;
}

/* xfree PTR
 * Free, ignoring a passed NULL value. */
void xfree(void *v) {
    if (v) free(v);
}

/* xstrdup:
 * Strdup, aborting on failure. */
char *xstrdup(const char *s) {
    char *t;
    t = xmalloc(strlen(s) + 1);
    strcpy(t, s);
    return t;
}
#endif  /* !MTRACE_DEBUGGING */

/* xstrndup STRING COUNT
 * Allocate a new buffer and copy in to it the first COUNT bytes of STRING,
 * terminating it with a null. */
char *xstrndup(const char *s, const size_t count) {
    char *S;
    S = xmalloc(count + 1);
    memcpy(S, s, count);
    S[count] = 0;
    return S;
}

/* md5_digest DATA COUNT MD5
 * Save in MD5 the MD5 digest of the first COUNT bytes of DATA. */
void md5_digest(const void *v, const size_t n, unsigned char *md5) {
    md5_ctx ctx;
    MD5Init(&ctx);
    MD5Update(&ctx, (unsigned char*)v, n);
    MD5Final(md5, &ctx);
}

/* md5_digest_str DATA COUNT BASE64
 * Return a static string containing a printable representation of the MD5 hash
 * of the first COUNT bytes of DATA; in hex by default or in base64 if BASE64
 * is nonzero. */
char *md5_digest_str(const void *v, const size_t n, const int base64) {
    unsigned char md5[16], *p;
    static char res[33] = {0};
    char *q;
    md5_digest(v, n, md5);
    if (base64) {
        /* Base 64 encoding per RFC2045 as from LDAP. */
        const char b64[] = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (p = md5, q = res; p < md5 + 16; p += 3, q += 4) {
            char s[5] = "====";
#define P(i)    (p + i > md5 + 16 ? *(p + i) : 0)
            s[0] = b64[P(0) >> 2];
            s[1] = b64[(P(0) & 0x3 << 4) | (P(1) & 0xf0 >> 4)];
            if (p + 1 < md5 + 16)
                s[2] = b64[(P(1) & 0xf << 2) | (P(2) & 0xc0 >> 4)];
            if (p + 2 < md5 + 16)
                s[3] = b64[P(2) & 0x3f];
            strcat(res, s);
#undef P
        }
    } else {
        /* Conventional hex encoding. */
        for (p = md5, q = res; p < md5 + 16; ++p, q += 2)
            sprintf(q, "%02x", (unsigned int)*p);
    }

    return res;
}
