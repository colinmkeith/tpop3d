/*
 * util.h:
 * global utility stuff for tpop3d
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

/* syslog(3) replacement */
void print_log(int priority, const char *fmt, ...);

/* write(2) replacement */
ssize_t xwrite(int fd, const void *buf, size_t count);

#endif /* __UTIL_H_ */
