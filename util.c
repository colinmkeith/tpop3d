/*
 * util.c:
 * Various utility functions for tpop3d.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

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

