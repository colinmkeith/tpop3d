/*
 * config.c: config file parsing
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.1  2000/09/26 22:23:36  chris
 * Initial revision
 *
 *
 */

static const char rcsid[] = "$Id$";

#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "config.h"
#include "stringmap.h"

#define MAX_CONFIG_LINE     2048

stringmap read_config_file(const char *f) {
    stringmap S;
    FILE *fp;
    char *line = (char*)malloc(MAX_CONFIG_LINE);
    int i = 1;
    if (!line) return NULL;

    fp = fopen(f, "rt");
    if (!fp) goto fail;

    S = stringmap_new();
    if (!S) goto fail;

    while (!feof(fp)) {
        char *p, *q, *r, *s;
        fgets(line, MAX_CONFIG_LINE, fp);

        p = strpbrk(line, "#\n");
        if (p) *p = 0;
        
        p = line + strspn(line, " \t");
        q = strchr(line, ':');

        if (q) {
            ++q;

            r = p + strcspn(p, " \t:");
            if (r != p) {
                *r = 0;

                q += strspn(q, " \t");
                r = q + strlen(q) - 1;
                while (strchr(" \t", *r) && r > q) --r;
                *(r + 1) = 0;

                if (r > q) {
                    item *I;
                    if ((I = stringmap_insert(S, p, item_ptr(strdup(q))))) {
                        syslog(LOG_ERR, "%s:%d: warning: repeated directive `%s'", f, i, p);
                        fprintf(stderr, "%s:%d: warning: repeated directive `%s'\n", f, i, p);
                    }
                }
            }
        }

        ++i;
    }

fail:
    if (fp) fclose(fp);
    if (line) free(line);

    return S;
}
