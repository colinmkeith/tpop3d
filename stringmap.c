/*
 * stringmap.c: sucky implementation of binary trees
 *
 * This makes no attempt to balance the tree, so has bad worst-case behaviour.
 * Also, I haven't implemented removal of items from the tree. So sue me.
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

#include <stdlib.h>
#include <string.h>

#include "stringmap.h"
#include "vector.h"

/* stringmap_new:
 * Allocate memory for a new stringmap.
 */
stringmap stringmap_new() {
    stringmap S = (stringmap)malloc(sizeof(struct _stringmap));

    if (!S) return NULL;

    memset(S, 0, sizeof(struct _stringmap));
}

/* stringmap_delete:
 * Free memory for a stringmap.
 */
void stringmap_delete(stringmap S) {
    if (!S) return;
    if (S->l) stringmap_delete(S->l);
    if (S->g) stringmap_delete(S->g);

    free(S->key);
    free(S);
}

/* stringmap_delete_free:
 * Free memory for a stringmap, and the objects contained in it, assuming that
 * they are pointers to memory allocated by malloc(3).
 */
void stringmap_delete_free(stringmap S) {
    if (!S) return;
    if (S->l) stringmap_delete(S->l);
    if (S->g) stringmap_delete(S->g);

    free(S->key);
    free(S->d.v);
    free(S);
}

/* stringmap_insert:
 * Insert into S an item having key k and value d. Returns an existing key
 * or NULL if it was inserted.
 */
item *stringmap_insert(stringmap S, const char *k, const item d) {
    if (!S) return 0;
    if (S->key == NULL) {
        S->key = strdup(k);
        S->d   = d;
        return NULL;
    } else {
        stringmap S2;
        for (S2 = S;;) {
            int i = strcmp(k, S2->key);
            if (i == 0) return &(S2->d);
            else if (i < 0)
                if (S2->l) S2 = S2->l;
                else {
                    S2->l = stringmap_new();
                    S2->l->key = strdup(k);
                    S2->l->d   = d;
                    return NULL;
                }
            else if (i > 0)
                if (S2->g) S2 = S2->g;
                else {
                    S2->g = stringmap_new();
                    S2->g->key = strdup(k);
                    S2->g->d   = d;
                    return NULL;
                }
        }
    }
}

/* stringmap_find:
 * Find in d an item having key k in the stringmap S, returning the item found
 * on success NULL if no key was found.
 */
item *stringmap_find(const stringmap S, const char *k) {
    stringmap S2;
    if (!S || S->key == NULL) return 0;
    for (S2 = S;;) {
        int i = strcmp(k, S2->key);
        if (i == 0) return &(S2->d);
        else if (i < 0)
            if (S2->l) S2 = S2->l;
            else return NULL;
        else if (i > 0)
            if (S2->g) S2 = S2->g;
            else return NULL;
    }
}
