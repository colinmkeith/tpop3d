/*
 * errprintf.c:
 * Sprintf, allowing %m -> strerror(errno).
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

/* verrprintf:
 * Returns a static string with the appropriate arguments printed into it.
 * (Replaced the dynamically allocating one with a static-buffer based
 * alternative, since it isn't possible to call vsnprintf(..., ap) in a loop,
 * as the arg list can't be reset. D'oh.) */
char *verrprintf(const char *fmt, va_list ap) {
    char *e = strerror(errno);
    const char *p, *q;
    char fmtbuf[1024];
    static char errbuf[1024];

    *fmtbuf = 0;

    /* First, we need to substitute errors into the string.
     * XXX this would not be safe in the presence of very long format strings
     * in the rest of the code, but we can guarantee that won't happen.... */
    for (p = fmt, q = strstr(p, "%m"); q; p = q, q = strstr(p, "%m")) {
        strncat(fmtbuf, p, q - p);
        strcat(fmtbuf, e);
        q += 2;
    }

    strcat(fmtbuf, p);

    vsnprintf(errbuf, sizeof(errbuf), fmtbuf, ap);

    return errbuf;
}
