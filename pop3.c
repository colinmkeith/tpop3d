/*
 * pop3.c: implementation of rfc1939
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

#include <stdio.h>
#include <stdlib.h>

#include "authswitch.h"
#include "connection.h"

/* trimcpy:
 * Make a copy of a string, removing leading or trailing whitespace.
 */
static char *trimcpy(const char *s) {
    const char *p, *q, *r;
    char *t;
    if (!s) return NULL;
    r = s + strlen(s);
    for (p = s; p < r && strstr(" \t", *p); ++p);
    for (q = r - 1; q > p && strstr(" \t", *p); --q);
    if (p == q) return NULL;
    t = (char*)malloc(q - p + 1);
    if (!t) return NULL;
    strncpy(t, p, q - p);
    return t;
}

/* connection_do:
 * Makes a command do something on a connection, returning a code indicating
 * what the caller should do.
 */
enum connection_action connection_do(connection c, const pop3command p) {
    if (c->state == authorisation) {
        switch (p->cmd) {
        case USER:
            if (c->user)
                connection_sendresponse(c, 0, "But you already said \"USER\".");
            else {
                c->user = trimcpy(p->tail);
                if (!c->user) connection_sendresponse(c, 0, "Tell me your name, knave!");
            }

        case PASS:
            if (c->pass)
                connection_sendresponse(c, 0, "But you already said \"PASS\".");
            else {
                c->pass = trimcpy(p->tail);
                if (!c->pass) connection_sendresponse(c, 0, "You must give a password.");
            }
            
        case APOP: {
            }
            
        case QUIT:
            return close_connection;
            
        default:
            connection_sendresponse(c, 0, "Not now. First tell me your name and password.");
        }

        if (!c->a && c->user && c->pass) {
            c->a = authcontext_new_user_pass(c->user, c->pass);
            if (c->a) connection_sendresponse(c, 1, "Welcome aboard.");
            else {
                connection_sendresponse(c, 0, "Lies! Try again!");
                ++c->n_auth_tries;
                if (c->n_auth_tries == MAX_AUTH_TRIES) return close_connection;
            }
        }

    } else if (c->state == transaction) { 
        
    } else {
        /* can't happen */
    }
}
