/*
 * tokenise.c: break a string into a list of tokens
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.1  2000/10/31 23:17:29  chris
 * Initial revision
 *
 *
 */

static const char rcsid[] = "$Id$";

#include <stdlib.h>
#include <string.h>

#include "tokenise.h"
#include "util.h"
#include "vector.h"

/* chomp:
 * Remove a CR/CRLF-type combination from the end of a string.
 */
void chomp(char *str) {
    char *p;
    p = str + strlen(str) - 1;
    while (p >= str && strchr("\r\n", *p)) *(p--) = 0;
}

/* tokenise_string:
 * Break a string into tokens, using the separator characters in seps. The
 * return value is a tokens object which contains a copy of the string and a
 * vector of pointers to the individual tokens in it.
 */
tokens tokens_new(const char *str, const char *seps) {
    tokens T;
    char *p, *r;
    T = (tokens)malloc(sizeof(struct _tokens));
    if (!T) return NULL;
    T->str = strdup(str);
    if (!(T->str)) {
        free(T);
        return NULL;
    }
    T->toks = vector_new();
    if (!(T->toks)) {
        free(T);
        free(T->str);
        return NULL;
    }
    
    p = strtok_r(T->str, seps, &r);
    while (p) {
        vector_push_back(T->toks, item_ptr(p));
        p = strtok_r(NULL, seps, &r);
    };

    return T;
}

/* tokens_delete:
 * Free a tokens object.
 */
void tokens_delete(tokens T) {
    if (!T) return;
    if (T->str) free(T->str);
    if (T->toks) vector_delete(T->toks);
    free(T);
    
}
