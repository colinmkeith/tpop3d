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

void print_log(int priority, const char *fmt, ...);
ssize_t xwrite(int fd, const void *buf, size_t count);
int daemon(int nochdir, int noclose);

#ifdef __SVR4
int inet_aton(const char *s, struct in_addr *ip);
#endif

#endif /* __UTIL_H_ */
