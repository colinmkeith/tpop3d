/*
 * config.c:
 * config file parsing
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "config.h"
#include "stringmap.h"
#include "util.h"

#define MAX_CONFIG_LINE     2048

/* read_config_file:
 * Read a configuration file consisting of key: value tuples, returning a
 * stringmap of the results. Prints errors to stderr, rather than using
 * syslog, since this file is called at program startup. Returns 1 on success
 * or 0 on failure.
 */
stringmap read_config_file(const char *f) {
    stringmap S = NULL;
    FILE *fp;
    char *line = xmalloc(MAX_CONFIG_LINE);
    int i = 1;
    if (!line) return NULL;

    fp = fopen(f, "rt");
    if (!fp) {
        fprintf(stderr, "%s: %s\n", f, strerror(errno));
        goto fail;
    }

    S = stringmap_new();
    if (!S) goto fail;

    while (fgets(line, MAX_CONFIG_LINE, fp)) {
        char *key, *value, *r;

        for (r = line + strlen(line) - 1; r > line && *r == '\n'; *(r--) = 0);

        /* Get continuation lines. Ugly. */
        while (*(line + strlen(line) - 1) == '\\') {
            if (!fgets(line + strlen(line) - 1, MAX_CONFIG_LINE - strlen(line), fp))
                break;
            for (r = line + strlen(line) - 1; r > line && *r == '\n'; *(r--) = 0);
        }

        /* Strip comment. */
        key = strpbrk(line, "#\n");

        if (key) *key = 0;
        /*    foo  : bar baz quux
         * key^    ^value
         */
        key = line + strspn(line, " \t");
        value = strchr(line, ':');

        if (value) {
            /*    foo  : bar baz quux
             * key^  ^r ^value
             */
            ++value;

            r = key + strcspn(key, " \t:");
            if (r != key) {
                item *I;
                *r = 0;

                /*    foo\0: bar baz quux
                 * key^      ^value      ^r
                 */
                value += strspn(value, " \t");
                r = value + strlen(value) - 1;
                while (strchr(" \t", *r) && r > value) --r;
                *(r + 1) = 0;

                /* (Removed check for zero length value.) */

                /* Check that this is a valid key. */
                if (!is_cfgdirective_valid(key))
                    fprintf(stderr, _("%s:%d: warning: unknown directive `%s'\n"), f, i, key);
                else if ((I = stringmap_insert(S, key, item_ptr(strdup(value)))))
                    fprintf(stderr, _("%s:%d: warning: repeated directive `%s'\n"), f, i, key);
            }
        }

        memset(line, 0, MAX_CONFIG_LINE); /* security paranoia */

        ++i;
    }

fail:
    if (fp) fclose(fp);
    if (line) xfree(line);

    return S;
}

/* config_get_int:
 * Get an integer value from a config string. Returns 1 on success, -1 on
 * failure, or 0 if no value was found.
 */
extern stringmap config; /* in main.c */

int config_get_int(const char *directive, int *value) {
    item *I = stringmap_find(config, directive);
    char *s, *t;
    if (!value) return -1;
    if (!I) return 0;

    s = (char*)I->v;
    if (!*s) return -1;
    errno = 0;
    *value = strtol(s, &t, 10);
    if (*t) return -1;

    return errno == ERANGE ? -1 : 1;
}

/* config_get_float:
 * Get an integer value from a config string. Returns 1 on success, -1 on
 * failure, or 0 if no value was found.
 */
int config_get_float(const char *directive, float *value) {
    item *I = stringmap_find(config, directive);
    char *s, *t;
    if (!value) return -1;
    if (!I) return 0;

    s = (char*)I->v;
    if (!*s) return -1;
    errno = 0;
    *value = strtod(s, &t);
    if (*t) return -1;

    return errno == ERANGE ? -1 : 1;
}

