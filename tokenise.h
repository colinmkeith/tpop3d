/*
 * tokenise.h: break a string into a list of tokens
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.1  2000/10/31 23:17:29  chris
 * Initial revision
 *
 *
 */

#ifndef __TOKENISE_H_ /* include guard */
#define __TOKENISE_H_

#include "vector.h"

typedef struct _tokens {
    char *str;
    vector toks;
} *tokens;

/* tokenise.c */
void chomp(char *str);
tokens tokens_new(const char *str, const char *seps);
void tokens_delete(tokens T);

#endif /* __TOKENISE_H_ */
