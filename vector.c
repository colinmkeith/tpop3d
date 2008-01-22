/*
 * vector.c:
 * simple vectors
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

#include "vector.h"
#include "util.h"

vector vector_new(void) {
    vector v;
 
    alloc_struct(_vector, v);

    v->ary = xcalloc(16, sizeof *v->ary);
    v->n = 16;
    v->n_used = 0;
    return v;
}

void vector_delete(vector v) {
    xfree(v->ary);
    xfree(v);
}

void vector_delete_free(vector v) {
    item *i;
    vector_iterate(v, i) {
        xfree(i->v);
    }
    xfree(v->ary);
    xfree(v);
}

void vector_push_back(vector v, const item t) {
    if (v->n_used == v->n) vector_reallocate(v, v->n * 2);
    v->ary[v->n_used++] = t;
}

void vector_pop_back(vector v) {
    if (v->n_used > 0) {
        --v->n_used;
        if (v->n_used < v->n / 2) vector_reallocate(v, v->n / 2);
    }
}

item vector_back(vector v) {
    return v->ary[v->n_used - 1];
}

item *vector_remove(vector v, item *t) {
    if (t >= v->ary + v->n_used) return NULL;
    if (t < v->ary + v->n_used - 1)
        memmove(t, t + 1, (v->n_used - (t - v->ary)) * sizeof(item));
    memset(v->ary + v->n_used--, 0, sizeof(item));
    if (v->n_used < v->n / 2 && v->n > 16) {
        size_t i = t - v->ary;
        vector_reallocate(v, v->n / 2);
        t = v->ary + i;
    }
    return t;
}

void vector_reallocate(vector v, const size_t n) {
    if (n < v->n_used || n <= 0) return;
    v->ary = xrealloc(v->ary, n * sizeof(item));
    memset(v->ary + v->n_used, 0, (v->n - v->n_used) * sizeof(item));
    v->n = n;
}
