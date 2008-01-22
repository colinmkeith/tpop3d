/*
 * stringmap.h:
 * map of strings
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

#ifndef __STRINGMAP_H_ /* include guard */
#define __STRINGMAP_H_

#include "vector.h"

typedef struct _stringmap {
    char *key;
    item d;
    struct _stringmap *l, *g;
} *stringmap;

stringmap stringmap_new(void);
void      stringmap_delete(stringmap);
void      stringmap_delete_free(stringmap);

/* Try to insert an item into a stringmap, returning 1 if the map already
 * contained an item with that key.
 */
item     *stringmap_insert(stringmap, const char*, const item);
/* Find an item in a stringmap */
item     *stringmap_find(const stringmap, const char*);

#endif /* __STRINGMAP_H_ */
