/*
 * util.h:
 * Global utility stuff for tpop3d
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __UTIL_H_ /* include guard */
#define __UTIL_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef TPOP3D_VERSION
#   define TPOP3D_VERSION   "(unknown)"
#endif

#ifndef PAGESIZE
#   define PAGESIZE        getpagesize()
#endif

#ifndef DOMAIN_SEPARATORS
#   define DOMAIN_SEPARATORS    "@%!:"
#endif

#if 0
/* Primitive memory-leak debugging. */
char *mystrdup(char *f, int l, const char *s);
void *mymalloc(char *f, int l, const size_t n);
void myfree(char *f, int l, void *p);
void *myrealloc(char *f, int l, void *p, const size_t n);

#define strdup(a)       mystrdup(__FILE__, __LINE__, a)
#define malloc(a)       mymalloc(__FILE__, __LINE__, a)
#define free(a)         myfree(__FILE__, __LINE__, a)
#define realloc(a, b)   myrealloc(__FILE__, __LINE__, a, b)
#endif

/* reallocating strncat. */
char *xstrncat(char *pfx, const char *sfx, const size_t n);

/* Function for substituting $(...) in strings. */
struct sverr {
    enum {sv_ok = 0, sv_syntax, sv_unknown, sv_range, sv_nullvalue } code;
    char *msg;
    off_t offset;
};

char *substitute_variables(const char *spec, struct sverr *err, const int nvars, ...);

/* Replacement logging functions. */
void log_init(void);
void log_print(int priority, const char *fmt, ...);

/* Restarting write(2). */
ssize_t xwrite(int fd, const void *buf, size_t count);
#define try_write(a, b, c)      (xwrite((a), (b), (c)) == (c))

/* Become a daemon. */
int daemon(int nochdir, int noclose);

int write_file(int fd, int sck, size_t msgoffset, size_t skip, size_t msglength, int n);

/* Look up group or user ids. */
int parse_uid(const char *user, uid_t *u);
gid_t parse_gid(const char *group, gid_t *g);

/* Some systems do not have inet_aton. */
#ifndef HAVE_INET_ATON
int inet_aton(const char *s, struct in_addr *ip);
#endif /* HAVE_INET_ATON */

/* We use strtok_r, but not all systems have it. */
#ifndef HAVE_STRTOK_R
char *strtok_r(char *s, const char *delim, char **saveptr);     /* GNU implementation in strtok_r.c */
#endif

/* Turn a 16-byte buffer into a binary string. */
char *hex_digest(const unsigned char *u);

/* Vice versa. */
int unhex_digest(const char *from, unsigned char *to);

/* Memory allocation wrappers. */
#ifndef MTRACE_DEBUGGING
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t m);
void *xrealloc(void *w, size_t n);
void xfree(void *v);
char *xstrdup(const char *s);
#else
/* Malloc wrappers are incompatible with mtrace debugging because the log file
 * produced by mtrace records only the innermost calling stack frame, and
 * therefore reports all leaks as occurring in xmalloc, xcalloc etc. */
#   define xmalloc  malloc
#   define xcalloc  calloc
#   define xrealloc realloc
#   define xfree    free
#   define xstrdup  strdup
#endif /* !MTRACE_DEBUGGING */

char *xstrndup(const char *s, const size_t count);

/* MD5 digests. */
void md5_digest(const void *v, const size_t n, unsigned char *md5);
char *md5_digest_str(const void *v, const size_t n, const int base64);

/* Optional internationalisation support. */
#ifdef WITH_I18N
#   include <gettext.h>
#   define _(String) gettext(String)
#else
#   define _(String) String
#endif /* WITH_I18N */

#endif /* __UTIL_H_ */
