/*
 * vector.c:
 * simple vectors
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <string.h>

#include "vector.h"
#include "util.h"

vector vector_new() {
    vector v = (vector)malloc(sizeof(struct _vector));
    if (!v) return NULL;
    memset(v, 0, sizeof(struct _vector));
    v->ary = (item*)malloc(16 * sizeof(item));
    v->n = 16;
    v->n_used = 0;
    return v;
}

void vector_delete(vector v) {
    free(v->ary);
    free(v);
}

void vector_delete_free(vector v) {
    item *i;
    vector_iterate(v, i) {
        free(i->v);
    }
    free(v->ary);
    free(v);
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
    v->ary = realloc(v->ary, n * sizeof(item));
    memset(v->ary + v->n_used, 0, (v->n - v->n_used) * sizeof(item));
    v->n = n;
}
