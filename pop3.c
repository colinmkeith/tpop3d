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

int append_domain;  /* Do we automatically try user@domain if user alone fails to authenticate? */
int strip_domain;   /* Automatically try user if user@domain fails? */
int apop_only;      /* Disconnect any client which says USER, unless their
                       connection is secured. */
int log_bad_pass;   /* Log bad passwords for support purposes. */

/* do_capa CONNECTION COMMAND
 * CAPA command; list capabilities. */
static enum connection_action do_capa(connection c) {
    const char *capas[] = {
            "PIPELINING", "TOP", "USER", "UIDL",
#ifdef REVEAL_IMPLEMENTATION
            "IMPLEMENTATION tpop3d-" TPOP3D_VERSION,
#endif
#ifdef USE_TLS
            "STLS",
#endif
            NULL /* last element must be NULL */
        }, **p;

    connection_sendresponse(c, 1, _("Capability list follows"));
    for (p = capas; *p; ++p) {
        if (strcmp(*p, "USER") == 0 && (apop_only && !c->secured))
            continue;
        
#ifdef USE_TLS
        if (strcmp(*p, "STLS") == 0 && c->l->tls.mode != stls)
            continue;
#endif

        connection_sendline(c, *p);
    }

    connection_sendline(c, ".");
    return do_nothing;
}

/* do_user CONNECTION COMMAND
 * USER command; supply username of client. Returns 1 on success or 0 on
 * failure. */
static int do_user(connection c, const pop3command p) {
    if (p->toks->num != 2) {
        connection_sendresponse(c, 0, _("No, that's not right."));
        return 0;
    } else if (c->user) {
        connection_sendresponse(c, 0, _("But you already said `USER'."));
        return 0;
    } else {
        c->user = xstrdup((char*)p->toks->toks[1]);
        if (!c->user)
#ifndef NO_SNIDE_COMMENTS
            connection_sendresponse(c, 0, _("Tell me your name, knave!"));
#else
            connection_sendresponse(c, 0, _("USER command must be followed by a username."));
#endif
        return 1;
    }
}

/* do_pass CONNECTION COMMAND
 * PASS command; supply password of user. Returns 1 on success or 0 on
 * failure. */
static int do_pass(connection c, const pop3command p) {
    if (p->toks->num != 2) {
        connection_sendresponse(c, 0, _("No, that's not right."));
        return 0;
    } else if (c->pass) {
        connection_sendresponse(c, 0, _("But you already said `PASS'."));
        return 0;
    } else {
        c->pass = xstrdup(p->toks->toks[1]);
        if (!c->pass)
            connection_sendresponse(c, 0, _("You must give a password."));
        return 1;
    }
}

/* do_apop CONNECTION COMMAND
 * APOP command; supply MD5 authentication data. */
static enum connection_action do_apop(connection c, const pop3command p) {
    char *name, *hexdigest;
    unsigned char digest[16];

    ++c->n_auth_tries;

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

    if (!name || *name == 0) {
        connection_sendresponse(c, 0, _("That's not right."));
        return do_nothing;
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

    c->a = authcontext_new_apop(name, NULL, c->domain, c->timestamp, digest, c->remote_ip, c->local_ip);

    /* Maybe retry authentication with an added or removed domain name. */
    if (!c->a && (strip_domain || append_domain)) {
        int n, len;
        len = strlen(name);
        n = strcspn(name, DOMAIN_SEPARATORS);
        if (append_domain && c->domain && n == len)
            /* OK, if we have a domain name, try appending that. */
            c->a = authcontext_new_apop(name, name, c->domain, c->timestamp, digest, c->remote_ip, c->local_ip);
        else if (strip_domain && n != len) {
            /* Try stripping off the supplied domain name. */
            char *u;
            u = xstrdup(name);
            u[n] = 0;
            c->a = authcontext_new_apop(u, NULL, NULL, c->timestamp, digest, c->remote_ip, c->local_ip);
            xfree(u);
        }
    }

    if (c->a) {
        /* Now save a new ID string for this client. */
        xfree(c->idstr);
        c->idstr =xmalloc(strlen(c->a->user) + 2 + strlen(inet_ntoa(c->sin.sin_addr)) + 16);
        sprintf(c->idstr, "[%d]%s(%s)", c->s, c->a->user, inet_ntoa(c->sin.sin_addr));

        c->state = transaction;
        return fork_and_setuid;
    } else {
        /* Authentication failed. */
        connection_freeze(c);
        if (c->n_auth_tries == MAX_AUTH_TRIES) {
#ifndef NO_SNIDE_COMMENTS
            connection_sendresponse(c, 0, _("This is ridiculous. I give up."));
#else
            connection_sendresponse(c, 0, _("Too many authentication attempts."));
#endif

            log_print(LOG_ERR, _("connection_do: client `%s': username `%s': failed to log in after %d attempts"), c->idstr, name, MAX_AUTH_TRIES);
            return close_connection;
        } else {
#ifndef NO_SNIDE_COMMENTS
            connection_sendresponse(c, 0, _("Lies! Try again!"));
#else
            connection_sendresponse(c, 0, _("Authentication failed."));
#endif
            log_print(LOG_ERR, _("connection_do: client `%s': username `%s': %d authentication failures"), c->idstr, name, c->n_auth_tries);
            return do_nothing;
        }
    }
}

/* do_list CONNECTION MSGNUM
 * LIST command; MSGNUM is the argument or -1 if none was specified. */
void do_list(connection c, const int msg_num) {
    /* Gives exact sizes taking account of the "From " lines. */
    if (msg_num != -1) {
        struct indexpoint *curmsg;
        curmsg = c->m->index + msg_num;
        if (curmsg->deleted)
            connection_sendresponse(c, 0, _("That message is no more."));
        else {
            char response[32] = {0};
            snprintf(response, 31, "%d %d", 1 + msg_num, (int)(curmsg->msglength - curmsg->length - 1));
            connection_sendresponse(c, 1, response);
        }
    } else {
        struct indexpoint *m;
        int nn = 0;
        if (!(connection_sendresponse(c, 1, _("Scan list follows:"))))
            return;
        for (m = c->m->index; m < c->m->index + c->m->num; ++m) {
            if (!m->deleted) {
                char response[32] = {0};
                snprintf(response, 31, "%d %d", 1 + m - c->m->index, (int)(m->msglength - m->length - 1));
                if (!(connection_sendline(c, response)))
                    return;
                ++nn;
            }
        }
        connection_sendline(c, ".");
        /* That might have taken a long time. */
        c->idlesince = time(NULL);
        if (verbose)
            log_print(LOG_DEBUG, _("do_list: client %s: sent %d-line scan list"), c->idstr, nn + 1);
    }
}

/* do_uidl CONNECTION MSGNUM
 * UIDL command: MSGNUM is the argument or -1 if none was specified. */
static void do_uidl(connection c, const int msg_num) {
    /* It isn't guaranteed that these IDs are unique; it is likely, though.
     * See RFC1939. */
    if (msg_num != -1) {
        struct indexpoint *curmsg;
        curmsg = c->m->index + msg_num;
        if (curmsg->deleted)
            connection_sendresponse(c, 0, _("That message is no more."));
        else {
            char response[64] = {0};
            snprintf(response, 63, "%d %s", 1 + msg_num, hex_digest(curmsg->hash));
            connection_sendresponse(c, 1, response);
        }
    } else {
        struct indexpoint *m;
        int nn = 0;
        if (!(connection_sendresponse(c, 1, _("ID list follows:"))))
            return;
        for (m = c->m->index; m < c->m->index + c->m->num; ++m) {
            if (!m->deleted) {
                char response[64] = {0};
                snprintf(response, 63, "%d %s", 1 + m - c->m->index, hex_digest(m->hash));
                if (!connection_sendline(c, response))
                    return;
                ++nn;
            }
        }
        connection_sendline(c, ".");
        /* That might have taken a long time. */
        c->idlesince = time(NULL);
        if (verbose)
            log_print(LOG_DEBUG, _("do_uidl: client %s: sent %d-line unique ID list"), c->idstr, nn + 1);
        return;
    }
}

/* do_retr CONNECTION MSGNUM
 * RETR command; send whole of message MSGNUM. */
static enum connection_action do_retr(connection c, const int msg_num) {
    if (msg_num != -1) {
        struct indexpoint *curmsg;
        curmsg = c->m->index + msg_num;
        if (curmsg->deleted)
            connection_sendresponse(c, 0, _("That message is no more."));
        else {
            int n;
            
            if (verbose)
                log_print(LOG_DEBUG, _("do_retr: client %s: sending message %d (%d bytes)"),
                        c->idstr, msg_num + 1, (int)curmsg->msglength);
            
            if ((n = c->m->sendmessage(c->m, c, msg_num, -1)) == -2)
                return close_connection;

            /* That might have taken a long time. */
            c->idlesince = time(NULL);
            if (verbose) {
                if (n >= 0)
                    log_print(LOG_DEBUG, _("do_retr: client %s: sent message %d"), c->idstr, msg_num + 1);
                else
                    log_print(LOG_DEBUG, _("do_retr: client %s: failed to send message %d"), c->idstr, msg_num + 1);
            }
        }
    } else
        connection_sendresponse(c, 0, _("Which message do you want to see?"));
    return do_nothing;
}

/* do_top CONNECTION MSGNUM NUM
 * TOP command; send headers and first NUM lines of message MSGNUM. */
static enum connection_action do_top(connection c, const int msg_num, const int nlines) {
    struct indexpoint *curmsg;
    curmsg = c->m->index + msg_num;

    if (msg_num == -1)
        connection_sendresponse(c, 0, _("What do you want to see?"));
    else if (nlines == -1)
        connection_sendresponse(c, 0, _("But how much do you want to see?"));
    else if (curmsg->deleted)
        connection_sendresponse(c, 0, _("That message is no more."));
    else {
        int n;
        
        if (verbose)
            log_print(LOG_DEBUG, _("do_top: client %s: sending headers and up to %d lines of message %d (< %d bytes)"),
                    c->idstr, nlines, msg_num + 1, (int)curmsg->msglength);
        
        if ((n = c->m->sendmessage(c->m, c, msg_num, nlines)) == -2)
            return close_connection;

        /* That might have taken a long time. */
        c->idlesince = time(NULL);
        if (verbose) {
            if (n >= 0)
                log_print(LOG_DEBUG, _("do_top: client %s: sent headers and up to %d lines of message %d"), c->idstr, nlines, msg_num + 1);
            else
                log_print(LOG_DEBUG, _("do_top: client %s: failed to send message %d"), c->idstr, msg_num + 1);
        }
    }
    
    return do_nothing;
}

/* do_dele
 * DELE command; delete message. */
void do_dele(connection c, const int msg_num) {
    struct indexpoint *curmsg;
    curmsg = c->m->index + msg_num;

    if (msg_num == -1)
        connection_sendresponse(c, 0, _("But which message do you want to delete?"));
    else {
        curmsg->deleted = 1;
        ++c->m->numdeleted;
        c->m->sizedeleted += curmsg->msglength;
        connection_sendresponse(c, 1, _("Done."));
    }
}

/* connection_do CONNECTION COMMAND
 * Have CONNECTION perforem COMMAND, returning a code indicating what the
 * caller should do. */
enum connection_action connection_do(connection c, const pop3command p) {
    /* This breaks the RFC, but is sensible. */
    if (p->cmd != NOOP && p->cmd != UNKNOWN) c->idlesince = time(NULL);

    if (c->state == authorisation) {
        /* Authorisation state: gather username and password or whatever. */
        switch (p->cmd) {
            case CAPA:
                return do_capa(c);
            
            case USER:
                if (apop_only && !c->secured) {
                    connection_sendresponse(c, 0, _("Sorry, you must use APOP"));
                    return close_connection;
                } else if (!do_user(c, p))
                    return do_nothing;
                break;

            case PASS:
                if (apop_only && !c->secured) {
                    connection_sendresponse(c, 0, _("Sorry, you must use APOP"));
                    return close_connection;
                } else if (!do_pass(c, p))
                    return do_nothing;
                break;

            case APOP:
                return do_apop(c, p);

            case QUIT:
#ifndef NO_SNIDE_COMMENTS
                connection_sendresponse(c, 1, _("Fine. Be that way."));
#else
                connection_sendresponse(c, 1, _("Done."));
#endif
                return close_connection;

            case STLS:
#ifdef USE_TLS
                if (c->secured) {
                    connection_sendresponse(c, 0, _("You're already using TLS"));
                    return do_nothing;
                } else if (c->l->tls.mode == stls) {
                    struct ioabs_tls *newio;
                    if (!(connection_sendresponse(c, 1, _("Begin TLS negotiation"))))
                        return close_connection;
                    if ((newio = ioabs_tls_create(c, c->l))) {
                        log_print(LOG_INFO, _("connection_do: client %s: negotiating TLS connection"), c->idstr);
                        c->io->destroy(c);
                        c->io = (struct ioabs*)newio;
                        return do_nothing;
                    } else {
                        /* Otherwise we've issued an OK response but haven't
                         * managed to negotiate a TLS connection. */
                        log_print(LOG_INFO, _("connection_do: client %s: tried and failed to negotiate TLS connection; closing connection"), c->idstr);
                        return close_connection;
                    }
                }
#endif
                log_print(LOG_INFO, _("connection_do: client %s: asked for TLS, not available"), c->idstr);
                connection_sendresponse(c, 0, _("Sorry, TLS not available"));
                return do_nothing;

            case UNKNOWN:
#ifndef NO_SNIDE_COMMENTS
                connection_sendresponse(c, 0, _("Do you actually know how to use this thing?"));
#else
                connection_sendresponse(c, 0, _("The command sent is invalid or unimplemented."));
#endif
                return do_nothing;

            default:
                connection_sendresponse(c, 0, _("Not now. First log in."));
                return do_nothing;
        }

        /* Do we now have enough information to authenticate using USER/PASS? */
        if (!c->a && c->user && c->pass) {
            c->a = authcontext_new_user_pass(c->user, NULL, c->domain, c->pass, c->remote_ip, c->local_ip);
            
            /* Maybe retry authentication with an added or removed domain name. */
            if (!c->a && (append_domain || strip_domain)) {
                int n, len;
                len = strlen(c->user);
                n = strcspn(c->user, DOMAIN_SEPARATORS);
                if (append_domain && c->domain && n == len)
                    /* OK, if we have a domain name, try appending that. */
                    c->a = authcontext_new_user_pass(c->user, c->user, c->domain, c->pass, c->remote_ip, c->local_ip);
                else if (strip_domain && n != len) {
                    /* Try stripping off the supplied domain name. */
                    char *u;
                    u = xstrdup(c->user);
                    u[n] = 0;
                    c->a = authcontext_new_user_pass(u, NULL, NULL, c->pass, c->remote_ip, c->local_ip);
                    xfree(u);
                }
            }

            if (c->a) {
                /* Now save a new ID string for this client. */
                xfree(c->idstr);
                c->idstr =xmalloc(strlen(c->a->user) + 2 + strlen(inet_ntoa(c->sin.sin_addr)) + 16);
                sprintf(c->idstr, "[%d]%s(%s)", c->s, c->a->user, inet_ntoa(c->sin.sin_addr));

                memset(c->pass, 0, strlen(c->pass));
                c->state = transaction;
                return fork_and_setuid; /* Code in main.c sends response in case of error. */
            } else {
                enum connection_action act;

                /*
                 * It is useful for ISPs to be able to log failing passwords
                 * sent by misconfigured clients. This is an invasion of
                 * privacy, but there we go.
                 */
                if (log_bad_pass)
                    log_print(LOG_INFO, _("connection_do: client `%s': username `%s': failing password is `%s'"), c->idstr, c->user, c->pass);
                            
                connection_freeze(c);
                ++c->n_auth_tries;
                if (c->n_auth_tries == MAX_AUTH_TRIES) {
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse(c, 0, _("This is ridiculous. I give up."));
#else
                    connection_sendresponse(c, 0, _("Too many authentication attempts."));
#endif
                    log_print(LOG_ERR, _("connection_do: client `%s': username `%s': failed to log in after %d attempts"), c->idstr, c->user, MAX_AUTH_TRIES);
                    act = close_connection;
                } else {
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse(c, 0, _("Lies! Try again!"));
#else
                    connection_sendresponse(c, 0, _("Authentication failed."));
#endif
                    log_print(LOG_ERR, _("connection_do: client `%s': username `%s': %d authentication failures"), c->idstr, c->user, c->n_auth_tries);
                    act = do_nothing;
                }

                memset(c->pass, 0, strlen(c->pass));
                xfree(c->pass);
                c->pass = NULL;

                xfree(c->user);
                c->user = NULL;
                
                return act;
            }
        } else {
            connection_sendresponse(c, 1, c->pass ? _("What's your name?") : _("Tell me your password."));
            return do_nothing;
        }
    } else if (c->state == transaction) { 
        /* Transaction state: do things to mailbox. */
        char *a = NULL;
        int num_args, msg_num = -1, nlines = -1;
        struct indexpoint *i, *curmsg;
        mailbox curmbox;
        char response[32] = {0};

        curmbox = c->m; /* this connection's mailbox */
        num_args = p->toks->num - 1;

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
         * number. */
        if (num_args >= 1) {
            a = p->toks->toks[1];
            if (a && strlen(a) > 0) {
                char *b;
                msg_num = strtol(a, &b, 10);
                --msg_num; /* RFC1939 demands that mailspools be indexed from 1 */
                if (!(b && !*b && b != a && msg_num >= 0 && msg_num < curmbox->num)) {
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse(c, 0, _("That does not compute."));
#else
                    connection_sendresponse(c, 0, _("Command argument should be numeric."));
#endif
                    return do_nothing;
                }
                curmsg = c->m->index + msg_num;
            }
        }

        /* The second argument is only ever used with TOP and is a number of
         * lines. */
        if (num_args == 2) {
            if (p->cmd == TOP) {
                a = p->toks->toks[2];
                if (a && strlen(a) > 0) {
                    char *b;
                    nlines = strtol(a, &b, 10);
                    if (!(b && !*b && b != a && nlines >= 0)) {
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
            case CAPA:
                return do_capa(c);

            case LIST:
                do_list(c, msg_num);
                break;

            case UIDL:
                do_uidl(c, msg_num);
                break;

            case DELE:
                do_dele(c, msg_num);
                break;

            case RETR:
                return do_retr(c, msg_num);

            case TOP:
                return do_top(c, msg_num, nlines);

            case STAT:
                snprintf(response, 31, "%d %d", curmbox->num - curmbox->numdeleted, curmbox->totalsize - curmbox->sizedeleted);
                connection_sendresponse(c, 1, response);
                break;

            case RSET:
                for (i = curmbox->index; i < curmbox->index + curmbox->num; ++i) i->deleted = 0;
                curmbox->numdeleted = 0;
                curmbox->sizedeleted = 0;
                connection_sendresponse(c, 1, _("Done."));
                break;

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

            case STLS:
#ifndef NO_SNIDE_COMMENTS
                connection_sendresponse(c, 0, _("It's a bit late for that now, isn't it?"));
#else
                connection_sendresponse(c, 0, _("STLS command available only in AUTHORIZATION stat"));
#endif
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

/* connection_start_transaction CONNECTION
 * Put CONNECTION in the `transaction' state, opening the mailbox. Returns 1
 * on success or 0 on failure. */
int connection_start_transaction(connection c) {
    if (!c) return 0;
    
    if (c->a->gid != getgid()) {
        log_print(LOG_ERR, _("connection_start_transaction: wrong gid"));
        return 0;
    }
    if (c->a->uid != getuid()) {
        log_print(LOG_ERR, _("connection_start_transaction: wrong uid"));
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
