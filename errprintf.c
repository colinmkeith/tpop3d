/*
 * errprintf.c:
 * Sprintf, allocating memory and allowing %m = strerror(errno).
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
 * Returns a malloc'd string with the appropriate arguments printed into it.
 */
#define GUESS 32
char *verrprintf(const char *fmt, va_list ap) {
    size_t l = GUESS;
    int n;
    char *s, *e = strerror(errno), *t;
    size_t le = strlen(e);
    const char *p, *q;
    
    if (!(s = malloc(l))) return NULL;
    memset(s, 0, l);

    /* First, we need to substitute errors into the string. */
/*
    for (p = fmt, q = strstr(p, "%m"); q && *p; p = q, q = strstr(p, "%m")) {
        s = xstrncat(s, p, q - p);
        s = xstrncat(s, e, le);
        q += 2;
    }
*/
/*    s = xstrncat(s, p, strlen(p));*/
    for (p = fmt, q = strstr(p, "%m"); q; p = q, q = strstr(p, "%m")) {
        if ((q - p + le) > l - strlen(s)) {
            l = (q - p + le) - strlen(s) + 1;
            s = realloc(s, l);
        }
        strncat(s, p, q - p);
        strcat(s, e);
        q += 2;
    }
    if (strlen(p) > (l - strlen(s))) {
        l = strlen(s) + strlen(p) + 1;
        s = realloc(s, l);
    }

    strcat(s, p);

    /* Now, need to use the generated string as a format string to pass to vsnprintf. */
    while (1) {
        t = (char*)malloc(n = l);
        n = vsnprintf(t, n, s, ap);
        if (n > -1 && n < l) {
            free(s);
            return t;
        }
        if (n > -1) l = n + 1;  /* Cope with vsnprintf returning either the required amount of space, or -1 to indicate "need more". */
        else l *= 2;
        if (!(t = realloc(t, l))) return NULL;
    }
}
