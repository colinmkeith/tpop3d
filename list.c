/*
 * list.c: doubly-linked list
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

static const char rcsid[] = "$Id$";

#include <stdlib.h>

#include "list.h"
#include "vector.h"

list list_new() {
    list l;
    l = (list)malloc(sizeof(struct _list));
    if (!l) return NULL;
    memset(l, 0, sizeof(struct _list));
    return l;
}

void list_delete(list l) {
    listitem i;
    if (!l) return;
    list_iterate(l, i) if (i->prev) free(i->prev);
    free(l);
}

void list_push_back(list l, const item i) {
    listitem I;
    if (!l) return;
    I = (listitem)malloc(sizeof(struct _listitem));
    I->d = i;
    I->next = NULL;
    I->prev = l->back;
    if (l->back) l->back->next = I;
    l->back = I;
    /* Empty list? */
    if (!l->front) l->front = I;
}

void list_pop_back(list l) {
    listitem I;
    if (!l || !l->back) return;
    I = l->back;
    l->back = l->back->prev;
    if (I == l->front) l->front = NULL;
    if (I) free(I);
}

void list_push_front(list l, const item i) {
    listitem I;
    if (!l) return;
    I = (listitem)malloc(sizeof(struct _listitem));
    I->d = i;
    I->prev = NULL;
    I->next = l->front;
    if (l->front) l->front->prev = I;
    l->front = I;
    /* Empty list? */
    if (!l->back) l->back = I;
}

void list_pop_front(list l) {
    listitem I;
    if (!l || !l->front) return;
    I = l->back;
    l->back = l->back->prev;
    if (I == l->front) l->front = NULL;
    if (I) free(I);
}

listitem list_remove(list l, listitem I) {
    if (I->prev) I->prev->next = I->next;
    if (I->next) I->next->prev = I->prev;

    if (l->front == I) l->front = I->next;
    if (l->back  == I) l->back  = I->prev;
    
    if (I->next) {
        free(I);
        return I->next;
    } else if (I->prev) {
        free(I);
        return I->prev;
    } else {
        free(I);
        return NULL;
    }
}
