/*
 * tokenise.h: break a string into a list of tokens
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

#ifndef __TOKENISE_H_ /* include guard */
#define __TOKENISE_H_

/* tokens:
 * Structure associated with tokenising a string. */
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
