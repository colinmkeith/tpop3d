/*
 * pop3.c:
 * implementation of rfc1939 POP3
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>    /* define struct sockaddr_in before arpa/inet.h's macros */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "authswitch.h"
#include "connection.h"
#include "util.h"

extern int verbose;

/* connection_do:
 * Makes a command do something on a connection, returning a code indicating
 * what the caller should do.
 */
int append_domain;  /* Do we automatically try user@domain if user alone fails to authenticate? */

enum connection_action connection_do(connection c, const pop3command p) {
    /* This breaks the RFC, but is sensible. */
    if (p->cmd != NOOP && p->cmd != UNKNOWN) c->idlesince = time(NULL);
    
    if (c->state == authorisation) {
        /* Authorisation state: gather username and password. */
        switch (p->cmd) {
        case USER:
            if (p->toks->num != 2) {
                connection_sendresponse(c, 0, _("No, that's not right."));
                return do_nothing;
            } else if (c->user) {
                connection_sendresponse(c, 0, _("But you already said `USER'."));
                return do_nothing;
            } else {
                c->user = strdup((char*)p->toks->toks[1]);
                if (!c->user) {
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse(c, 0, _("Tell me your name, knave!"));
#else
                    connection_sendresponse(c, 0, _("USER command must be followed by a username."));
#endif
                    return do_nothing;
                }
            }
            break;

        case PASS:
            if (p->toks->num != 2) {
                connection_sendresponse(c, 0, _("No, that's not right."));
                return do_nothing;
            } else if (c->pass) {
                connection_sendresponse(c, 0, _("But you already said `PASS'."));
                return do_nothing;
            } else {
                c->pass = strdup(p->toks->toks[1]);
                if (!c->pass) {
                    connection_sendresponse(c, 0, _("You must give a password."));
                    return do_nothing;
                }
            }
            break;
            
        case APOP: {
                /* Interpret an APOP name digest command */
                char *name, *hexdigest;
                unsigned char digest[16];

                if (p->toks->num != 3) {
                    connection_sendresponse(c, 0, _("No, that's not right."));
                    return do_nothing;
                }

                name =      (char*)p->toks->toks[1];
                hexdigest = (char*)p->toks->toks[2];

                if (c->n_auth_tries == MAX_AUTH_TRIES) {
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse(c, 0, _("This is ridiculous. I give up."));
#else
                    connection_sendresponse(c, 0, _("Too many authentication attempts."));
#endif
                    return close_connection;
                }

                ++c->n_auth_tries;

                if (!name || *name == 0) {
                    connection_sendresponse(c, 0, _("That's not right."));
                }
                
                if (strlen(hexdigest) != 32) {
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse(c, 0, _("Try again, but get it right next time."));
#else
                    connection_sendresponse(c, 0, _("Authentication string is invalid."));
#endif
                    return do_nothing;
                }

                /* Obtain digest */
                if (!unhex_digest(hexdigest, digest)) {
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse(c, 0, _("Clueless bunny!"));
#else
                    connection_sendresponse(c, 0, _("Authentication failed."));
#endif
                    return do_nothing;
                }

                c->a = authcontext_new_apop(name, c->timestamp, digest, c->domain);
                
                if (!c->a && append_domain && c->domain && strcspn(name, "@%!") == strlen(name)) {
                    /* OK, if we have a domain name, try appending that. */
                    char *nn = (char*)malloc(strlen(name) + strlen(c->domain) + 2);
                    strcpy(nn, name);
                    strcat(nn, "@");
                    strcat(nn, c->domain);
                    c->a = authcontext_new_apop(nn, c->timestamp, digest, c->domain);
                    free(nn);

                }

                if (c->a) {
                    /* Now save a new ID string for this client. */
                    free(c->idstr);
                    c->idstr =(char*)malloc(strlen(c->a->user) + 2 + strlen(inet_ntoa(c->sin.sin_addr)) + 16);
                    sprintf(c->idstr, "[%d]%s(%s)", c->s, c->a->user, inet_ntoa(c->sin.sin_addr));

                    c->state = transaction;
                    return fork_and_setuid;
                } else {
                    if (c->n_auth_tries == MAX_AUTH_TRIES) {
#ifndef NO_SNIDE_COMMENTS
                        connection_sendresponse(c, 0, _("This is ridiculous. I give up."));
#else
                        connection_sendresponse(c, 0, _("Too many authentication attempts."));
#endif

                        print_log(LOG_ERR, _("connection_do: client `%s' failed to log in after %d attempts"), c->idstr, MAX_AUTH_TRIES);
                        return close_connection;
                    } else {
                        ++c->n_auth_tries;
#ifndef NO_SNIDE_COMMENTS
                        connection_sendresponse(c, 0, _("Lies! Try again!"));
#else
                        connection_sendresponse(c, 0, _("Authentication failed."));
#endif
                        return do_nothing;
                    }
                }
            }
            break;
            
        case QUIT:
#ifndef NO_SNIDE_COMMENTS
            connection_sendresponse(c, 1, _("Fine. Be that way."));
#else
            connection_sendresponse(c, 1, _("Done."));
#endif
            return close_connection;

        case UNKNOWN:
#ifndef NO_SNIDE_COMMENTS
            connection_sendresponse(c, 0, _("Do you actually know how to use this thing?"));
#else
            connection_sendresponse(c, 0, _("The command sent is invalid or unimplemented."));
#endif
            return do_nothing;
            
        default:
            connection_sendresponse(c, 0, _("Not now. First tell me your name and password."));
            return do_nothing;
        }

        /* Do we now have enough information to authenticate using USER/PASS? */
        if (!c->a && c->user && c->pass) {
            c->a = authcontext_new_user_pass(c->user, c->pass, c->domain);
            if (!c->a && append_domain && c->domain && strcspn(c->user, "@%!") == strlen(c->user)) {
                /* OK, if we have a domain name, try appending that. */
                char *nn = (char*)malloc(strlen(c->user) + strlen(c->domain) + 2);
                strcpy(nn, c->user);
                strcat(nn, "@");
                strcat(nn, c->domain);
                c->a = authcontext_new_user_pass(nn, c->pass, c->domain);
                free(nn);
            }

            if (c->a) {
                /* Now save a new ID string for this client. */
                free(c->idstr);
                c->idstr =(char*)malloc(strlen(c->a->user) + 2 + strlen(inet_ntoa(c->sin.sin_addr)) + 16);
                sprintf(c->idstr, "[%d]%s(%s)", c->s, c->a->user, inet_ntoa(c->sin.sin_addr));

                memset(c->pass, 0, strlen(c->pass));
                c->state = transaction;
                return fork_and_setuid; /* Code in main.c sends response in case of error. */
            } else {
                free(c->user);
                c->user = NULL;
                memset(c->pass, 0, strlen(c->pass));
                free(c->pass);
                c->pass = NULL;

                ++c->n_auth_tries;
                if (c->n_auth_tries == MAX_AUTH_TRIES) {
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse(c, 0, _("This is ridiculous. I give up."));
#else
                    connection_sendresponse(c, 0, _("Too many authentication attempts."));
#endif
                    print_log(LOG_ERR, _("connection_do: client `%s' failed to log in after %d attempts"), c->idstr, MAX_AUTH_TRIES);
                    return close_connection;
                } else {
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse(c, 0, _("Lies! Try again!"));
#else
                    connection_sendresponse(c, 0, _("Authentication failed."));
#endif
                    return do_nothing;
                }
            }
        } else {
            connection_sendresponse(c, 1, c->pass ? _("What's your name?") : _("Tell me your password."));
            return do_nothing;
        }
    } else if (c->state == transaction) { 
        /* Transaction state: do things to mailbox. */
        char *a = NULL;
        int num_args = p->toks->num - 1, have_msg_num = 0, msg_num = 0, have_arg2 = 0, arg2 = 0;
        struct indexpoint *curmsg = NULL;
        mailbox curmbox = c->m; /* this connection's mailbox */
        
        /* No command has more than two arguments. */
        if (num_args > 2) {
#ifndef NO_SNIDE_COMMENTS
            connection_sendresponse(c, 0, _("Already, you have told me too much."));
#else
            connection_sendresponse(c, 0, _("Too many arguments for command."));
#endif
            return do_nothing;
        }
        
        /* The first argument, if any, is always interpreted as a message
         * number.
         */
        if (num_args >= 1) {
            a = p->toks->toks[1];
            if (a && strlen(a) > 0) {
                char *b;
                msg_num = strtol(a, &b, 10);
                --msg_num; /* RFC1939 demands that mailspools be indexed from 1 */
                if (b && !*b && b != a && msg_num >= 0 && msg_num < curmbox->num) {
                    have_msg_num = 1;
                    curmsg = curmbox->index + msg_num;
                } else {
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse(c, 0, _("That does not compute."));
#else
                    connection_sendresponse(c, 0, _("Command argument should be numeric."));
#endif
                    return do_nothing;
                }
            }
        }

        /* The second argument is always a positive semi-definite numeric
         * parameter.
         */
        if (num_args == 2) {
            if (p->cmd == TOP) {
                have_arg2 = 0;
                a = p->toks->toks[2];
                if (a && strlen(a) > 0) {
                    char *b;
                    arg2 = strtol(a, &b, 10);
                    if (b && !*b && b != a && arg2 >= 0) have_arg2 = 1;
                    else {
#ifndef NO_SNIDE_COMMENTS
                        connection_sendresponse(c, 0, _("Can you actually count?"));
#else
                        connection_sendresponse(c, 0, _("Command argument should be numeric."));
#endif
                        return do_nothing;
                    }
                }
            } else {
                connection_sendresponse(c, 0, _("Nope, that doesn't sound right at all."));
                return do_nothing;
            }
        }
        
        switch (p->cmd) {
        case LIST:
            /* Gives exact sizes taking account of the "From " lines. */
            if (have_msg_num) {
                if (curmsg->deleted)
                    connection_sendresponse(c, 0, _("That message is no more."));
                else {
                    char response[32] = {0};
                    snprintf(response, 31, "%d %d", 1 + msg_num, curmsg->msglength - curmsg->length - 1);
                    connection_sendresponse(c, 1, response);
                }
            } else {
                struct indexpoint *m;
                int nn = 0;
                connection_sendresponse(c, 1, _("Scan list follows:"));
                for (m = curmbox->index; m < curmbox->index + curmbox->num; ++m) {
                    if (!m->deleted) {
                        char response[32] = {0};
                        snprintf(response, 31, "%d %d", 1 + m - curmbox->index, m->msglength - m->length - 1);
                        connection_sendline(c, response);
                        ++nn;
                    }
                }
                connection_sendline(c, ".");
                /* That might have taken a long time. */
                c->idlesince = time(NULL);
                if (verbose)
                    print_log(LOG_DEBUG, _("connection_do: client %s: sent %d-line scan list"), c->idstr, nn + 1);
            }
            break;

        case UIDL:
            /* It isn't guaranteed that these IDs are unique; it is likely,
             * though. See RFC1939.
             */
            if (have_msg_num) {
                if (curmsg->deleted)
                    connection_sendresponse(c, 0, _("That message is no more."));
                else {
                    char response[64] = {0};
                    print_log(LOG_INFO, "UIDL %d (hash = %s)", 1 + msg_num, hex_digest(curmsg->hash));
                    snprintf(response, 63, "%d %s", 1 + msg_num, hex_digest(curmsg->hash));
                    connection_sendresponse(c, 1, response);
                }
            } else {
                struct indexpoint *J;
                int nn = 0;
                print_log(LOG_INFO, "UIDL");
                connection_sendresponse(c, 1, _("ID list follows:"));
                for (J = curmbox->index; J < curmbox->index + curmbox->num; ++J) {
                    if (!J->deleted) {
                        char response[64] = {0};
                        snprintf(response, 63, "%d %s", 1 + J - curmbox->index, hex_digest(J->hash));
                        connection_sendline(c, response);
                        ++nn;
                    }
                }
                connection_sendline(c, ".");
                /* That might have taken a long time. */
                c->idlesince = time(NULL);
                if (verbose)
                    print_log(LOG_DEBUG, _("connection_do: client %s: sent %d-line unique ID list"), c->idstr, nn + 1);
            }
            break;

        case DELE:
            if (have_msg_num) {
                curmsg->deleted = 1;
                connection_sendresponse(c, 1, _("Done."));
                ++curmbox->numdeleted;
            } else
                connection_sendresponse(c, 0, _("Which message do you want to delete?"));
            break;

        case RETR:
            if (have_msg_num) {
                if (curmsg->deleted)
                    connection_sendresponse(c, 0, _("That message is no more."));
                else {
                    if (verbose)
                        print_log(LOG_DEBUG, _("connection_do: client %s: sending message %d (%d bytes)"),
                                    c->idstr, msg_num + 1, (int)curmsg->msglength);
                    connection_sendresponse(c, 1, _("Message follows:"));
                    if (!(curmbox)->send_message(curmbox, c->s, msg_num, -1)) {
                        connection_sendresponse(c, 0, _("Oops"));
                        return close_connection;
                    }
                    /* That might have taken a long time. */
                    c->idlesince = time(NULL);
                    if (verbose)
                        print_log(LOG_DEBUG, _("connection_do: client %s: sent message %d"), c->idstr, msg_num + 1);
                }
                break;
            } else {
                connection_sendresponse(c, 0, _("Which message do you want to see?"));
                break;
            }

        case TOP: {
                if (!have_msg_num) {
                    connection_sendresponse(c, 0, _("What do you want to see?"));
                    break;
                } else if (curmsg->deleted) {
                    connection_sendresponse(c, 0, _("That message is no more."));
                    break;
                } else if (!have_arg2) {
                    connection_sendresponse(c, 0, _("But how much do you want to see?"));
                    break;
                }
                
                if (verbose)
                    print_log(LOG_DEBUG, _("connection_do: client %s: sending headers and up to %d lines of message %d (< %d bytes)"),
                                c->idstr, arg2, msg_num + 1, (int)curmsg->msglength);
                connection_sendresponse(c, 1, _("Message follows:"));

                if (!(curmbox)->send_message(curmbox, c->s, msg_num, arg2)) {
                    connection_sendresponse(c, 0, _("Oops."));
                    return close_connection;
                }
                /* That might have taken a long time. */
                c->idlesince = time(NULL);
                if (verbose)
                    print_log(LOG_DEBUG, _("connection_do: client %s: sent headers and up to %d lines of message %d"), c->idstr, arg2, msg_num + 1);
                break;
            }
                

        case STAT: {
                char response[32] = {0};
                /* Size here is approximate as we don't strip off the "From "
                 * headers.
                 */
                snprintf(response, 31, "%d %d", curmbox->num, (int)curmbox->st.st_size);
                connection_sendresponse(c, 1, response);
                break;
            }

        case RSET: {
                struct indexpoint *i;
                for (i = curmbox->index; i < curmbox->index + curmbox->num; ++i) i->deleted = 0;
                curmbox->numdeleted = 0;
                connection_sendresponse(c, 1, _("Done."));
                break;
            }

        case QUIT:
            /* Now perform UPDATE */
            if ((curmbox)->apply_changes(curmbox)) connection_sendresponse(c, 1, _("Done"));
            else connection_sendresponse(c, 0, _("Something went wrong."));
            return close_connection;
            
        case NOOP:
            connection_sendresponse(c, 1, _("I'm still here."));
            break;

    case LAST:
            connection_sendresponse(c, 0, _("Sorry, the LAST command was removed in RFC1725."));
            break;

        default:
#ifndef NO_SNIDE_COMMENTS
            connection_sendresponse(c, 0, _("Do you actually know how to use this thing?"));
#else
            connection_sendresponse(c, 0, _("The command sent was invalid or unimplemented."));
#endif
            break;
        }

        return do_nothing;
    } else {
        /* Can't happen, but keep the compiler quiet... */
        connection_sendresponse(c, 0, _("connection_do: unknown state, closing connection."));
        return close_connection;
    }
}

/* connection_start_transaction:
 * Set up the connection into the "transaction" state. Returns 1 on success or
 * 0 on failure.
 */
int connection_start_transaction(connection c) {
    if (!c) return 0;
    
    if (c->a->gid != getgid()) {
        print_log(LOG_ERR, _("connection_start_transaction: wrong gid"));
        return 0;
    }
    if (c->a->uid != getuid()) {
        print_log(LOG_ERR, _("connection_start_transaction: wrong uid"));
        return 0;
    }
    
    if (c->a->mailbox) {
        c->m = mailbox_new(c->a->mailbox, c->a->mboxdrv);
        if (c->m == MBOX_NOENT) c->m = emptymbox_new(NULL);
    } else
        c->m = find_mailbox(c->a);

    if (!c->m) return 0;
    else return 1;
}
