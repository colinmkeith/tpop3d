/*
 * vector.h:
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

#ifndef __VECTOR_H_ /* include guard */
#define __VECTOR_H_

typedef union _item {
    void *v;
    long l;
} item;

#define _inline inline

static _inline item item_long(const long l) { item u; u.l = l; return u; }
static _inline item item_ptr(void *const v) { item u; u.v = v; return u; }

typedef struct _vector{
    item *ary;
    size_t n, n_used;
} *vector;

vector vector_new(void);
void vector_delete(vector);
void vector_delete_free(vector);

void  vector_push_back(vector, const item);
void  vector_pop_back(vector);
item vector_back(const vector);

item *vector_remove(vector, item *t);

void  vector_reallocate(vector, const size_t n);

/* A macro to iterate over a vector */
#define vector_iterate(_v, _t)  for ((_t) = (_v)->ary; (_t) < (_v)->ary + (_v)->n_used; ++(_t))

#endif /* __VECTOR_H_ */
