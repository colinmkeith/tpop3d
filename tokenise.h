/*
 * tokenise.h: break a string into a list of tokens
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __TOKENISE_H_ /* include guard */
#define __TOKENISE_H_

#include "vector.h"

typedef struct _tokens {
    char *str;
    char **toks;
    int num;
} *tokens;

/* tokenise.c */
void chomp(char *str);
tokens tokens_new(const char *str, const char *seps);
void tokens_delete(tokens T);

#endif /* __TOKENISE_H_ */
