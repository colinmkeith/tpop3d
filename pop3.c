/*
 * pop3.c: implementation of rfc1939 POP3
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.2  2000/09/26 22:23:36  chris
 * Various changes.
 *
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

static const char rcsid[] = "$Id$";

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

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
    for (p = s; p < r && strchr(" \t", *p); ++p);
    for (q = r - 1; q > p && strchr(" \t", *q); --q); ++q;
    if (p == q) return NULL;
    t = (char*)malloc(q - p + 2);
    if (!t) return NULL;
    memset(t, 0, q - p + 2);
    strncpy(t, p, q - p + 1);
    return t;
}

/* hex_digest:
 * Print a dump of a message hash.
 */
static char *hex_digest(const unsigned char *u) {
    static char hex[33] = {0};
    const unsigned char *p;
    char *q;
    for (p = u, q = hex; p < u + 16; ++p, q += 2)
        sprintf(q, "%02x", (unsigned int)*p);

    return hex;
}

/* connection_do:
 * Makes a command do something on a connection, returning a code indicating
 * what the caller should do.
 */
enum connection_action connection_do(connection c, const pop3command p) {
    if (c->state == authorisation) {
        /* Authorisation state: gather username and password. */
        switch (p->cmd) {
        case USER:
            if (c->user) {
                connection_sendresponse(c, 0, "But you already said \"USER\".");
                return do_nothing;
            } else {
                c->user = trimcpy(p->tail);
                if (!c->user) {
                    connection_sendresponse(c, 0, "Tell me your name, knave!");
                    return do_nothing;
                }
            }
            break;

        case PASS:
            if (c->pass) {
                connection_sendresponse(c, 0, "But you already said \"PASS\".");
                return do_nothing;
            } else {
                c->pass = trimcpy(p->tail);
                if (!c->pass) {
                    connection_sendresponse(c, 0, "You must give a password.");
                    return do_nothing;
                }
            }
            break;
            
        case APOP: {
                connection_sendresponse(c, 0, "Not implemented yet.");
                return do_nothing;
            }
            break;
            
        case QUIT:
            connection_sendresponse(c, 1, "Fine. Be that way.");
            return close_connection;

        case UNKNOWN:
            connection_sendresponse(c, 0, "Do you actually know how to use this thing?");
            return do_nothing;
            
        default:
            connection_sendresponse(c, 0, "Not now. First tell me your name and password.");
            return do_nothing;
        }

        if (!c->a && c->user && c->pass) {
            c->a = authcontext_new_user_pass(c->user, c->pass);
            if (c->a) {
                c->state = transaction;
                return fork_and_setuid; /* Code in main.c sends response in case of error. */
            } else {
                free(c->user);
                c->user = NULL;
                free(c->pass);
                c->pass = NULL;

                ++c->n_auth_tries;
                if (c->n_auth_tries == MAX_AUTH_TRIES) {
                    connection_sendresponse(c, 0, "This is ridiculous. I give up.");
                    return close_connection;
                } else {
                    connection_sendresponse(c, 0, "Lies! Try again!");
                    return do_nothing;
                }
            }
        } else {
            connection_sendresponse(c, 1, c->pass ? "What's your name?" : "Tell me your password.");
            return do_nothing;
        }

    } else if (c->state == transaction) { 
        /* Transaction state: do things to mailbox. */
        char *a = NULL;
        int msg_num, have_arg = 0, have_msg_num = 0;
        indexpoint I;
        
        if (p->tail) {
            have_arg = 1;
            a = trimcpy(p->tail);
            if (a && strlen(a) > 0) {
                char *b;
                msg_num = strtol(a, &b, 10);
                if (!b || b == a) msg_num = -1;
                else if (msg_num >= 0 && msg_num < c->m->index->n_used) {
                    have_msg_num = 1;
                    I = (indexpoint)c->m->index->ary[msg_num].v;
                    fprintf(stderr, "obtained msg_num = %d (%s)\n", msg_num, a);
                }
                free(a);
            }
        }
        
        switch (p->cmd) {
        case LIST:
            if (have_arg)
                if (have_msg_num)
                    if (I->deleted)
                        connection_sendresponse(c, 0, "That message is no more");
                    else {
                        char response[32];
                        snprintf(response, 31, "%d %d", msg_num, I->msglength);
                        connection_sendresponse(c, 1, response);
                    }
                else connection_sendresponse(c, 0, "Not a valid message number");
            else {
                item *J;
                connection_sendresponse(c, 1, "Scan list follows");
                vector_iterate(c->m->index, J) {
                    if (!((indexpoint)J->v)->deleted) {
                        char response[48];
                        snprintf(response, 47, "%d %d", J - c->m->index->ary, ((indexpoint)J->v)->msglength);
                        connection_sendline(c, response);
                    }
                }
                connection_sendline(c, ".");
            }
            break;

        case UIDL:
            if (have_arg)
                if (have_msg_num)
                    if (I->deleted)
                        connection_sendresponse(c, 0, "That message is no more");
                    else {
                        char response[64];
                        snprintf(response, 63, "%d %s", msg_num, hex_digest(I->hash));
                        connection_sendresponse(c, 1, response);
                    }
                else connection_sendresponse(c, 0, "Not a valid message number");
            else {
                item *J;
                connection_sendresponse(c, 1, "ID list follows");
                vector_iterate(c->m->index, J) {
                    if (!((indexpoint)J->v)->deleted) {
                        char response[64];
                        snprintf(response, 63, "%d %s", J - c->m->index->ary, hex_digest(((indexpoint)J->v)->hash));
                        connection_sendline(c, response);
                    }
                }
                connection_sendline(c, ".");
            }
            break;

        case DELE:
                if (have_msg_num) {
                    I->deleted = 1;
                    connection_sendresponse(c, 1, "Done");
                } else
                    connection_sendresponse(c, 0, "Which message do you want to delete?");
                break;

        case STAT: {
                char response[32];
                snprintf(response, 31, "%d %d", c->m->index->n_used, c->m->st.st_size);
                connection_sendresponse(c, 1, response);
                break;
            }
            
            
        case NOOP:
            connection_sendresponse(c, 1, "I'm still here");
            break;

        default:
            connection_sendresponse(c, 0, "Oops");
            break;
        }

        free(a);

        return do_nothing;
    } else {
        /* can't happen */
    }
}

/* connection_start_transaction:
 * Set up the connection into the "transaction" state. Returns 1 on success or
 * 0 on failure.
 */
int connection_start_transaction(connection c) {
    if (!c) return 0;
    
    if (c->a->uid != getuid() || c->a->gid != getgid()) {
        syslog(LOG_ERR, "connection_start_transaction: wrong uid/gid");
        return 0;
    }
    
    c->m = mailspool_new_from_file(c->a->mailspool);

    if (!c->m) return 0;
    else return 1;
}
