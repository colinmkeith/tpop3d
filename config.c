/*
 * config.c:
 * config file parsing
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

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
    char *line = (char*)malloc(MAX_CONFIG_LINE);
    int i = 1;
    if (!line) return NULL;

    fp = fopen(f, "rt");
    if (!fp) {
        fprintf(stderr, "%s: %s\n", f, strerror(errno));
        goto fail;
    }

    S = stringmap_new();
    if (!S) goto fail;

    while (!feof(fp)) {
        char *key, *value, *r;
        fgets(line, MAX_CONFIG_LINE, fp);

        key = strpbrk(line, "#\n");
        if (key) *key = 0;
        
        key = line + strspn(line, " \t");
        value = strchr(line, ':');

        if (value) {
            ++value;

            r = key + strcspn(key, " \t:");
            if (r != key) {
                *r = 0;

                value += strspn(value, " \t");
                r = value + strlen(value) - 1;
                while (strchr(" \t", *r) && r > value) --r;
                *(r + 1) = 0;

                if (r >= value) {
                    item *I;
                    if ((I = stringmap_insert(S, key, item_ptr(strdup(value))))) {
                        fprintf(stderr, "%s:%d: warning: repeated directive `%s'\n", f, i, key);
                    }
                }
            }
        }

        memset(line, 0, MAX_CONFIG_LINE); /* security paranoia */

        ++i;
    }

fail:
    if (fp) fclose(fp);
    if (line) free(line);

    return S;
}
