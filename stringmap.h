/*
 * stringmap.h: map of strings
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.1  2000/10/02 18:22:19  chris
 * Initial revision
 *
 *
 */

#ifndef __STRINGMAP_H_ /* include guard */
#define __STRINGMAP_H_

#include "vector.h"

typedef struct _stringmap {
    char *key;
    item d;
    struct _stringmap *l, *g;
} *stringmap;

stringmap stringmap_new();
void      stringmap_delete(stringmap);
void      stringmap_delete_free(stringmap);

/* Try to insert an item into a stringmap, returning 1 if the map already
 * contained an item with that key.
 */
item     *stringmap_insert(stringmap, const char*, const item);
/* Find an item in a stringmap */
item     *stringmap_find(const stringmap, const char*);

#endif /* __STRINGMAP_H_ */
