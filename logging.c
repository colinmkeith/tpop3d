/*
 * logging.c:
 * Logging for tpop3d.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
 *
 */

static const char rcsid[] = "$Id$";

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "config.h"
#include "util.h"

extern int log_stderr;      /* in main.c */

/* facil:
 * Log facility names and constants, used to allow configurable logging at
 * run time. Not all those defined in openlog(3) make sense, so only a few
 * are listed here. */
static struct logfac {
    char *name;
    int fac;
} facil[] = {
        {"mail",        LOG_MAIL},
#ifdef LOG_AUTHPRIV
        {"authpriv",    LOG_AUTHPRIV},
#endif
#ifdef LOG_AUTH
        {"auth",        LOG_AUTH},
#endif
        {"daemon",      LOG_DAEMON},
        {"user",        LOG_USER},
        
        {"local0",      LOG_LOCAL0},
        {"local1",      LOG_LOCAL1},
        {"local2",      LOG_LOCAL2},
        {"local3",      LOG_LOCAL3},
        {"local4",      LOG_LOCAL4},
        {"local5",      LOG_LOCAL5},
        {"local6",      LOG_LOCAL6},
        {"local7",      LOG_LOCAL7},
    };

#define NFACIL      (sizeof(facil) / sizeof(struct logfac))

static int log_fac;

/* log_init:
 * Start up logging. */
void log_init(void) {
    int fac = LOG_MAIL, warn = 0;
    char *s;

    if ((s = config_get_string("log-facility"))) {
        struct logfac *l;
        warn = 1;
        for (l = facil; l < facil + NFACIL; ++l)
            if (strcasecmp(l->name, s) == 0) {
                warn = 0;
                fac = l->fac;
                break;
            }
    }

    openlog("tpop3d", LOG_PID | LOG_NDELAY, fac);
    if (warn == 1)
        log_print(LOG_ERR, _("log_init: log-facility `%s' unknown, using `mail'"), s);

    log_fac = fac;
}


/* verrprintf:
 * Returns a static string with the appropriate arguments printed into it.
 * (Replaced the dynamically allocating one with a static-buffer based
 * alternative, since it isn't possible to call vsnprintf(..., ap) in a loop,
 * as the arg list can't be reset. D'oh.) */
static char *verrprintf(const char *fmt, va_list ap) {
    char *e = strerror(errno);
    const char *p, *q;
    char fmtbuf[1024];
    static char errbuf[1024];

    *fmtbuf = 0;

    /* First, we need to substitute errors into the string. This would not be
     * safe in the presence of very long format strings in the rest of the
     * code, but we can guarantee that won't happen.... */
    for (p = fmt, q = strstr(p, "%m"); q; p = q, q = strstr(p, "%m")) {
        strncat(fmtbuf, p, q - p);
        strcat(fmtbuf, e);
        q += 2;
    }

    strcat(fmtbuf, p);

    vsnprintf(errbuf, sizeof(errbuf), fmtbuf, ap);

    return errbuf;
}

/* log_print:
 * Print a line to the log. */
void log_print(int priority, const char *fmt, ...) {
    char *s;
    va_list ap;
    va_start(ap, fmt);
    s = verrprintf(fmt, ap);
    va_end(ap);
    syslog(priority | log_fac, "%s", s);
    if (log_stderr) fprintf(stderr, "%s\n", s);
}


