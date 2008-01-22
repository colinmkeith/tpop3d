/*
 * tokenise.c:
 * Break a string into a list of tokens.
 *
 * Copyright (c) 2000 Chris Lightfoot.
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

#define _REENTRANT      /* needed on some systems to get strtok_r */
#include <stdlib.h>
#include <string.h>

#include "tokenise.h"
#include "util.h"

/* chomp:
 * Remove a CR/CRLF-type combination from the end of a string. */
void chomp(char *str) {
    char *p;
    p = str + strlen(str) - 1;
    while (p >= str && strchr("\r\n", *p)) *(p--) = 0;
}

/* tokenise_string:
 * Break a string into tokens, using the separator characters in seps. The
 * return value is a tokens object which contains a copy of the string and an
 * array of pointers to the individual tokens in it. */
tokens tokens_new(const char *str, const char *seps) {
    tokens T;
    char *p, *r;
    int nn = 4;
    
    alloc_struct(_tokens, T);

    T->str = xstrdup(str);
    T->toks = xcalloc(nn, sizeof *T->toks);
    
    p = strtok_r(T->str, seps, &r);
    while (p) {
        T->toks[T->num++] = p;
        if (T->num == nn) {
            T->toks = (char**)xrealloc(T->toks, sizeof(char*) * nn * 2);
            memset(T->toks + nn, 0, sizeof(char*) * nn);
            nn *= 2;
        }
        p = strtok_r(NULL, seps, &r);
    };

    return T;
}

/* tokens_delete:
 * Free a tokens object. */
void tokens_delete(tokens T) {
    if (!T) return;
    xfree(T->str);
    xfree(T->toks);
    xfree(T);
}
