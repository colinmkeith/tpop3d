/*
 * util.h:
 * global utility stuff for tpop3d
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __UTIL_H_ /* include guard */
#define __UTIL_H_

#ifndef TPOP3D_VERSION
#   define TPOP3D_VERSION   "(unknown)"
#endif

/*
#define strdup(a)   mystrdup(__FILE__, __LINE__, (a))
#define malloc(a)   mymalloc(__FILE__, __LINE__ ,(a))
#define free(a)     myfree(__FILE__, __LINE__, (a))
*/
/*
char *mystrdup(char *, int, char *);
void *mymalloc(char *, int, size_t);
void myfree(char *, int, void *);
*/

/* syslog(3) replacement */
void print_log(int priority, const char *fmt, ...);

#define syslog print_log

/* Some systems do not have inet_aton; use inet_ntop instead. */
#ifdef __SVR4 /* Solaris */
#   define inet_aton(a, b)      (inet_pton(AF_INET, (a), (b)) == 1)
#endif /* __SVR4 */

#endif /* __UTIL_H_ */
