/*
 * tokenise.c:
 * Break a string into a list of tokens.
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 * 
 */

static const char rcsid[] = "$Id$";

#define _REENTRANT      /* needed on some systems to get strtok_r */
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
 * return value is a tokens object which contains a copy of the string and an
 * array of pointers to the individual tokens in it.
 */
tokens tokens_new(const char *str, const char *seps) {
    tokens T;
    char *p, *r;
    int nn = 4;
    T = (tokens)malloc(sizeof(struct _tokens));
    memset(T, 0, sizeof(struct _tokens));
    if (!T) return NULL;
    T->str = strdup(str);
    if (!(T->str)) {
        free(T);
        return NULL;
    }
    T->toks = (char**)malloc(sizeof(char*) * nn);
    if (!(T->toks)) {
        free(T);
        free(T->str);
        return NULL;
    }
    memset(T->toks, 0, sizeof(char*) * nn);
    
    p = strtok_r(T->str, seps, &r);
    while (p) {
        T->toks[T->num++] = p;
        if (T->num == nn) {
            T->toks = (char**)realloc(T->toks, sizeof(char*) * nn * 2);
            memset(T->toks + nn, 0, sizeof(char*) * nn);
            nn *= 2;
        }
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
    if (T->toks) free(T->toks);
    free(T);
    
}
