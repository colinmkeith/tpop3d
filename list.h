/*
 * list.h:
 * doubly-linked list
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __LIST_H_ /* include guard */
#define __LIST_H_

#include "vector.h"

typedef struct _listitem {
    item d;
    struct _listitem *next, *prev;
} *listitem;

typedef struct _list {
    listitem front, back;
} *list;

list list_new();
void list_delete(list);
void list_delete_free(list);

void list_push_back(list, const item);
void list_pop_back(list);

void list_push_front(list, const item);
void list_pop_front(list);

listitem list_remove(list, listitem);

#define list_iterate(_l, _t)    for ((_t) = (_l)->front; (_t); (_t) ? (_t) = (_t)->next : 0)

#endif /* __LIST_H_ */
