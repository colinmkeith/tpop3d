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
#endif // HAVE_CONFIG_H

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    for (p = fmt, q = strstr(p, "%m"); q; p = q, q = strstr(p, "%m")) {
        while (((q - p) + le) > (l - strlen(s))) {
            l *= 2;
            s = realloc(s, l);
        }
        strncat(s, p, q - p);
        strcat(s, e);
        q += 2;
    }
    while ((fmt + strlen(fmt) - p) > l - strlen(s)) {
            l *= 2;
            if (!(s = realloc(s, l))) return NULL;
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
