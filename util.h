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

#include <sys/types.h>

#ifndef TPOP3D_VERSION
#   define TPOP3D_VERSION   "(unknown)"
#endif

#define PAGESIZE        getpagesize()

/* Function for substituting $(...) in strings. */
struct sverr {
    char *msg;
    off_t offset;
};

char *substitute_variables(const char *spec, struct sverr *err, const int nvars, ...);

/* Replacement logging function. */
void print_log(int priority, const char *fmt, ...);

/* Restarting write(2). */
ssize_t xwrite(int fd, const void *buf, size_t count);
#define try_write(a, b, c)      (xwrite((a), (b), (c)) == (c))

/* Become a daemon. */
int daemon(int nochdir, int noclose);

int write_file(int fd, int sck, size_t msgoffset, size_t skip, size_t msglength, int n);

#ifdef __SVR4
int inet_aton(const char *s, struct in_addr *ip);
#endif

/* Optional internationalisation support. */
#ifdef WITH_I18N
#   include <gettext.h>
#   define _(String) gettext(String)
#else
#   define _(String) String
#endif /* WITH_I18N */

/* Look up group or user ids. */
int parse_uid(const char *user, uid_t *u);
gid_t parse_gid(const char *group, gid_t *g);

#endif /* __UTIL_H_ */
