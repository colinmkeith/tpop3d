/*
 * stringmap.c: sucky implementation of binary trees
 *
 * This makes no attempt to balance the tree, so has bad worst-case behaviour.
 * Also, I haven't implemented removal of items from the tree. So sue me.
 *
 * Copyright (c) 2001 Chris Lightfoot.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <string.h>

#include "stringmap.h"
#include "vector.h"
#include "util.h"

/* stringmap_new:
 * Allocate memory for a new stringmap. */
stringmap stringmap_new() {
    stringmap S;
    alloc_struct(_stringmap, S);   
    return S;
}

/* stringmap_delete:
 * Free memory for a stringmap. */
void stringmap_delete(stringmap S) {
    if (!S) return;
    if (S->l) stringmap_delete(S->l);
    if (S->g) stringmap_delete(S->g);

    xfree(S->key);
    xfree(S);
}

/* stringmap_delete_free:
 * Free memory for a stringmap, and the objects contained in it, assuming that
 * they are pointers to memory allocated by xmalloc(3). */
void stringmap_delete_free(stringmap S) {
    if (!S) return;
    if (S->l) stringmap_delete_free(S->l);
    if (S->g) stringmap_delete_free(S->g);

    xfree(S->key);
    xfree(S->d.v);
    xfree(S);
}

/* stringmap_insert:
 * Insert into S an item having key k and value d. Returns an existing key
 * or NULL if it was inserted. */
item *stringmap_insert(stringmap S, const char *k, const item d) {
    if (!S) return 0;
    if (S->key == NULL) {
        S->key = xstrdup(k);
        S->d   = d;
        return NULL;
    } else {
        stringmap S2;
        for (S2 = S;;) {
            int i = strcmp(k, S2->key);
            if (i == 0) return &(S2->d);
            else if (i < 0) {
                if (S2->l) S2 = S2->l;
                else {
                    if (!(S2->l = stringmap_new())) return NULL;
                    S2->l->key = xstrdup(k);
                    S2->l->d   = d;
                    return NULL;
                }
            } else if (i > 0) {
                if (S2->g) S2 = S2->g;
                else {
                    if (!(S2->g = stringmap_new())) return NULL;
                    S2->g->key = xstrdup(k);
                    S2->g->d   = d;
                    return NULL;
                }
            }
        }
    }
}

/* stringmap_find:
 * Find in d an item having key k in the stringmap S, returning the item found
 * on success NULL if no key was found. */
item *stringmap_find(const stringmap S, const char *k) {
    stringmap S2;
    int i;
    if (!S || S->key == NULL) return 0;
    for (S2 = S;;) {
        i = strcmp(k, S2->key);
        if (i == 0) return &(S2->d);
        else if (i < 0) {
            if (S2->l) S2 = S2->l;
            else return NULL;
        } else if (i > 0) {
            if (S2->g) S2 = S2->g;
            else return NULL;
        }
    }
}
