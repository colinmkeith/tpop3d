/*
 * main.c:
 * main loop for pop3 server
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char copyright[] = "$Copyright: (c) 2001 Chris Lightfoot. All rights reserved. $";
static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "config.h"
#include "connection.h"
#include "errprintf.h"
#include "list.h"
#include "listener.h"
#include "pidfile.h"
#include "signals.h"
#include "stringmap.h"
#include "vector.h"
#include "util.h"

/* The socket send buffer is set to this, so that we don't end up in a
 * position that we send so much data that the client will not have received
 * all of it before we time them out.
 */
#define MAX_DATA_IN_FLIGHT      8192

/* Data structure representing the config file, and global variable which we
 * set from it.
 */
stringmap config;

/* Various configuration options. */
extern int append_domain;           /* Do we automatically try user@domain if user alone fails to authenticate? In pop3.c. */
int log_stderr;                     /* Are log messages also sent to standard error? */
int verbose;                        /* Should we be verbose about data going to/from the client? */
int timeout_seconds = 30;           /* How long a period of inactivity may elapse before a client is dropped. */

int max_running_children = 16;      /* How many children may exist at once. */
volatile int num_running_children = 0;  /* How many children are active. */

char *pidfile = NULL;               /* The name of a PID file to use; if NULL, don't use one. */

/* Variables representing the state of the server. */
int post_fork = 0;                  /* Is this a child handling a connection. */
connection this_child_connection;   /* Stored here so that if a signal terminates the child, the mailspool will still get unlocked. */

vector listeners;                   /* Listeners */
list connections;                   /* Active connections. */

/* Theory of operation:
 * The main loop is in net_loop, below; it calls listeners_ and
 * connections_pre_select, then calls select, then calls listeners_ and
 * connections_post_select. In the event that a server is forked to handle a
 * client, fork_child is called. The global variables listeners and
 * connections are used to handle this procedure.
 */


/* listeners_pre_select:
 * Called before the main select(2) so listening sockets can be polled.
 */
void listeners_pre_select(int *n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    item *t;
    vector_iterate(listeners, t) {
        int s = ((listener)t->v)->s;
        FD_SET(s, readfds);
        if (s > *n) *n = s;
    }
}

/* listeners_post_select:
 * Called after the main select(2) to allow listening sockets to sort
 * themselves out.
 */
void listeners_post_select(fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    item *t;
    vector_iterate(listeners, t) {
        listener L = (listener)t->v;
        if (FD_ISSET(L->s, readfds)) {
            struct sockaddr_in sin;
            size_t l = sizeof(sin);
            int s = accept(L->s, (struct sockaddr*)&sin, (int *)&l);
            int a = MAX_DATA_IN_FLIGHT;

            if (s == -1) {
                if (errno != EAGAIN) print_log(LOG_ERR, "net_loop: accept: %m");
            } else if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &a, sizeof(a)) == -1) {
                /* Set a small send buffer so that we get usefully blocking writes. */
                print_log(LOG_ERR, "handle_listeners: setsockopt: %m");
                close(s);
            } else if (fcntl(s, F_SETFL, 0) == -1) {
                /* Switch off non-blocking mode, in case it is inherited. */
                print_log(LOG_ERR, "handle_listeners: fcntl(F_SETFL): %m");
                close(s);
            } else {
                if (num_running_children >= max_running_children) {
                    char *m = _("-ERR Sorry, I'm too busy right now\r\n");
                    xwrite(s, m, strlen(m));
                    shutdown(s, 2);
                    close(s);
                    print_log(LOG_INFO, _("handle_listeners: rejected connection from %s owing to high load"), inet_ntoa(sin.sin_addr));
                } else {
                    connection c = connection_new(s, &sin, L->domain);
                    if (c) list_push_back(connections, item_ptr(c));
                    print_log(LOG_INFO, _("handle_listeners: client %s: connected"), c->idstr);
                }
            }
        }
    }
}

/* connections_pre_select:
 * Called before the main select(2) so connections can be polled.
 */
void connections_pre_select(int *n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    listitem I;
    list_iterate(connections, I) {
        int s = ((connection)I->d.v)->s;
        FD_SET(s, readfds);
        if (s > *n) *n = s;
    }
}

/* fork_child:
 * Handle forking a child to handle an individual connection. C and i are,
 * respectively, pointers to the connection and the listitem which holds it;
 * these are modified by the function, so are passed by reference.
 */
void fork_child(connection *C, listitem *i) {
#define c               (*C)
#define I               (*i)
    listitem J;
    item *t;
    post_fork = 1; /* This is right. See below. */
    switch(fork()) {
        case 0:
            /* Child. Dispose of listeners and connections other than this
             * one.
             */
            vector_iterate(listeners, t) listener_delete((listener)t->v);
            vector_delete(listeners);
            listeners = NULL;

            list_iterate(connections, J) {
                if (J->d.v != c) {
                    close(((connection)J->d.v)->s);
                    ((connection)J->d.v)->s = -1;
                    J = list_remove(connections, J);
                }
                if (!J) break;
            }

            /* We never access mailspools as root. */
            if (!c->a->uid) {
                print_log(LOG_ERR, _("fork_child: client %s: authentication context has UID of 0"), c->idstr);
                connection_sendresponse(c, 0, _("Everything's really bad"));
                connection_delete(c);
                exit(0);
            }

            /* Set our gid and uid to that appropriate for the mailspool, as decided by the auth switch. */
            if (setgid(c->a->gid) == -1) {
                print_log(LOG_ERR, "fork_child: setgid(%d): %m", c->a->gid);
                connection_sendresponse(c, 0, _("Something bad happened, and I just can't go on. Sorry."));
                connection_delete(c);
                exit(0);
            } else if (setuid(c->a->uid) == -1) {
                print_log(LOG_ERR, "fork_child: setuid(%d): %m", c->a->uid);
                connection_sendresponse(c, 0, _("Something bad happened, and I just can't go on. Sorry."));
                connection_delete(c);
                exit(0);
            }

            /* Get in to the `transaction' state, opening the mailbox. */
            if (connection_start_transaction(c)) {
                char s[512], *p;
                strcpy(s, _("Welcome aboard!"))
                strcat(s, " ");
                p = s + strlen(s);
                switch (c->m->index->n_used) {
                    case 0:
                        strcpy(p, _("You have no messages at all."));
                        break;

                    case 1:
                        strcat(p, _("You have exactly one message."));
                        break;

                    default:
                        sprintf(p, _("You have %d messages."), c->m->index->n_used);
                        break;
                }
                connection_sendresponse(c, 1, s);
                this_child_connection = c;
            } else {
                connection_sendresponse(c, 0, _("Unable to open mailbox; it may be locked by another concurrent session."));
                connection_delete(c);
                exit(0);
            }

            I = NULL;

            break;

        case -1:
            /* Error. */
            print_log(LOG_ERR, "fork_child: fork: %m");
            connection_sendresponse(c, 0, _("Everything was fine until now, but suddenly I realise I just can't go on. Sorry."));
            connection_delete(c);
            c = NULL;
            I = list_remove(connections, I);
            break;

        default:
            /* Parent. Dispose of our copy of this connection. */
            post_fork = 0;  /* Now SIGHUP will work again. */
            
            close(c->s);
            c->s = -1; /* Don't shutdown the socket */
            connection_delete(c);
            c = NULL;
            
            I = list_remove(connections, I);

            ++num_running_children;
    }
#undef c
#undef I
}

/* connections_post_select:
 * Called after the main select(2) to do stuff with connections.
 */
void connections_post_select(fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    listitem I;
    list_iterate(connections, I) {
        if (FD_ISSET(((connection)I->d.v)->s, readfds)) {
            /* Data is available on this socket. */
            int n;
            connection c = (connection)I->d.v;
            n = connection_read(c);
            if (n == 0) {
                /* Peer closed the connection */
                print_log(LOG_INFO, _("connections_post_select: connection_read: client %s: closed connection"), c->idstr);
                connection_delete(c);
                I = list_remove(connections, I);
                if (post_fork) exit(0);
                if (!I) break;
            } else if (n < 0 && errno != EINTR) {
                /* Some sort of error occurred, and we should close the connection. */
                print_log(LOG_ERR, _("connections_post_select: connection_read: client %s: disconnected: %m"), c->idstr);
                connection_delete(c);
                I = list_remove(connections, I);
                if (post_fork) exit(0);
                if (!I) break;
            } else {
                /* We read some data and should try to interpret command/s. */
                pop3command p;
                while (c && (p = connection_parsecommand(c))) {
                    switch(connection_do(c, p)) {
                        case close_connection:
                            connection_delete(c);
                            c = NULL;
                            I = list_remove(connections, I);
                            if (post_fork) exit(0);
                            break;

                        case fork_and_setuid:
                            if (num_running_children >= max_running_children) {
                                connection_sendresponse(c, 0, _("Sorry, I'm too busy right now"));
                                print_log(LOG_INFO, _("connections_post_select: client %s: rejected login owing to high load"), c->idstr);
                                connection_delete(c);
                                I = list_remove(connections, I);
                                c = NULL;
                                break;
                            } else fork_child(&c, &I);

                        default:;
                    }

                    pop3command_delete(p);

                    if (!I) break;
                }

                if (!I) break;
            }
        } else if (timeout_seconds && (time(NULL) > (((connection)(I->d.v))->idlesince + timeout_seconds))) {
            /* Connection has timed out. */
#ifndef NO_SNIDE_COMMENTS
            connection_sendresponse((connection)(I->d.v), 0, _("You can hang around all day if you like. I have better things to do."));
#else
            connection_sendresponse((connection)(I->d.v), 0, _("Client has been idle for too long."));
#endif
            print_log(LOG_INFO, "net_loop: timed out client %s", ((connection)I->d.v)->idstr);
            connection_delete((connection)(I->d.v));
            if (post_fork) exit(0);
            I = list_remove(connections, I);
            if (!I) break;
        }
    }
}

/* net_loop:
 * Accept connections and put them into an appropriate state, calling
 * setuid() and fork() when appropriate.
 */
volatile int foad = 0, restart = 0; /* Flags used to indicate that we should exit or should re-exec. */

#ifdef AUTH_OTHER
extern pid_t authchild_died;
extern int authchild_status;
#endif /* AUTH_OTHER */

void net_loop() {
    listitem J;
#ifdef AUTH_OTHER
    sigset_t chmask;
    sigemptyset(&chmask);
    sigaddset(&chmask, SIGCHLD);
#endif /* AUTH_OTHER */

    connections = list_new();

    print_log(LOG_INFO, _("net_loop: tpop3d version %s successfully started"), TPOP3D_VERSION);
    
    /* Main select() loop */
    while (!foad) {
        fd_set readfds;
        struct timeval tv = {1, 0}; /* Must be less than IDLE_TIMEOUT and small enough that termination on receipt of SIGTERM is timely. */
        int n = 0, e;

        FD_ZERO(&readfds);

        if (!post_fork) listeners_pre_select(&n, &readfds, NULL, NULL);

        connections_pre_select(&n, &readfds, NULL, NULL);

        e = select(n + 1, &readfds, NULL, NULL, &tv);
        if (e == -1 && errno != EINTR) {
            print_log(LOG_WARNING, "net_loop: select: %m");
        } else if (e >= 0) {
            /* Check for new incoming connections */
            if (!post_fork) listeners_post_select(&readfds, NULL, NULL);

            /* Monitor existing connections */
            connections_post_select(&readfds, NULL, NULL);
        }

#ifdef AUTH_OTHER
        /* It may be that the authentication child died; log the message here
         * to avoid doing something we shouldn't in the signal handler. We
         * block SIGCHLD while doing this.
         */
        sigprocmask(SIG_BLOCK, &chmask, NULL);
        if (authchild_died) {
            print_log(LOG_WARNING, _("net_loop: authentication child %d terminated with status %d"), (int)authchild_died, authchild_status);
            authchild_died = 0;
        }
        sigprocmask(SIG_UNBLOCK, &chmask, NULL);
#endif /* AUTH_OTHER */
    }

    /* Termination request received; we should close all connections in an
     * orderly fashion.
     */
    if (restart) print_log(LOG_INFO, _("net_loop: restarting on signal %d"),
            foad);
    else print_log(LOG_INFO, _("net_loop: terminating on signal %d"), foad);

    if (connections) {
        list_iterate(connections, J) connection_delete((connection)J->d.v);
        list_delete(connections);
    }
}

#define EXIT_REMOVING_PIDFILE(n) do { if (pidfile) remove_pid_file(pidfile); exit((n)); } while (0)

/* usage:
 * Print usage information.
 */
void usage(FILE *fp) {
    fprintf(fp, _(
"tpop3d, version %s\n"
"\n"
"Synopsis: tpop3d -h | [-f file] [-p file] [-d] [-v]\n"
"\n"
"  -h               Display this message\n"
"  -f file          Read configuration from file (default: /etc/tpop3d.conf)\n"
"  -p file          Write PID to file (default: don't use a PID file)\n"
"  -d               Do not detach from controlling terminal\n"
"  -v               Log traffic to/from server for debugging purposes\n"
"\n"
                ), TPOP3D_VERSION);

    /* Describe the compiled-in options. */
    authswitch_describe(fp);
    mailbox_describe(fp);

    fprintf(fp, _(
"tpop3d, copyright (c) 2000-2001 Chris Lightfoot <chris@ex-parrot.com>;\n"
"portions copyright (c) 2001 Mark Longair, Paul Makepeace.\n"
"home page: http://www.ex-parrot.com/~chris/tpop3d/\n"
"\n"
"This program is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License as published by\n"
"the Free Software Foundation; either version 2 of the License, or\n"
"(at your option) any later version.\n"
"\n"
                ));
}

/* main:
 * Read config file, set up authentication and proceed to main loop.
 */
char optstring[] = "+hdvf:p:";

int main(int argc, char **argv, char **envp) {
    item *I;
    int nodaemon = 0;
    char *configfile = "/etc/tpop3d.conf", c;
    int na;

    /* Read the options. */
    opterr = 0;
    while ((c = getopt(argc, argv, optstring)) != EOF) {
        switch(c) {
            case 'h':
                usage(stdout);
                return 0;

            case 'd':
                nodaemon = 1;
                log_stderr = 1;
                break;

            case 'v':
                verbose = 1;
                break;

            case 'f':
                configfile = optarg;
                break;

            case 'p':
                pidfile = optarg;
                break;

            case '?':
            default:
                if (optopt == 'f' && !optarg)
                    fprintf(stderr, _("tpop3d: option -f requires an argument\n"));
                else if (optopt == 'p' && !optarg)
                    fprintf(stderr, _("tpop3d: option -p requires an argument\n"));
                else
                    fprintf(stderr, _("tpop3d: unrecognised option -%c\n"), optopt);
                usage(stderr);
                return 1;
        }
    }

    /* Read the config file. */
    config = read_config_file(configfile);
    if (!config) return 1;

    /* Detach from controlling tty etc. */
    if (!nodaemon) daemon(0, 0);

    /* Start logging. */
    openlog("tpop3d", LOG_PID | LOG_NDELAY, LOG_MAIL);

    /* Try to write PID file. */
    if (pidfile) {
        switch (write_pid_file(pidfile)) {
            case pid_file_success:
                break;

            case pid_file_existence: {
                pid_t pid;
                switch (read_pid_file(pidfile, &pid)) {
                    case pid_file_success:
                        if (kill(pid, 0)) {
                            print_log(LOG_ERR, _("%s: stale PID file `%s'; exiting. Remove it and restart."), pidfile);
                            return 1;
                        } else {
                            print_log(LOG_ERR, _("%s: tpop3d already running, with process ID %d; exiting."), (int)pid);
                            return 1;
                        }
                        break;
                        
                    default:
                        print_log(LOG_ERR, _("%s: PID file seems to be invalid; exiting."), pidfile);
                        return 1;
                }
                break;
            }

            case pid_file_error:
                print_log(LOG_ERR, _("%s: %m: couldn't write PID file; exiting."), pidfile);
                return 1;
        }
    }

    /* Identify addresses on which to listen.
     * The syntax for these is <addr>[:port][(domain)].
     */
    I = stringmap_find(config, "listen-address");
    listeners = vector_new();
    if (I) {
        tokens t = tokens_new(I->v, " \t");
        item *J;

        vector_iterate(t->toks, J) {
            struct sockaddr_in sin = {0};
            listener L;
            char *s = J->v, *r = NULL, *domain = NULL;

            sin.sin_family = AF_INET;

            /* Specified domain. */
            r = strchr(s, '(');
            if (r) {
                if (*(s + strlen(s) - 1) != ')') {
                    print_log(LOG_ERR, _("%s: syntax for listen address `%s' is incorrect"), configfile, s);
                    continue;
                }

                *r++ = 0;
                *(r + strlen(r) - 1) = 0;
                domain = r;
            }
            
            /* Port. */
            r = strchr(s, ':');
            if (r) {
                *r++ = 0;
                sin.sin_port = atoi(r);
                if (!sin.sin_port) {
                    struct servent *se;
                    se = getservbyname(r, "tcp");
                    if (!se) {
                        print_log(LOG_ERR, _("%s: specified listen address `%s' has invalid port `%s'"), configfile, s, r);
                        continue;
                    } else sin.sin_port = se->s_port;
                } else sin.sin_port = htons(sin.sin_port);
            } else sin.sin_port = htons(110); /* pop-3 */
            
            /* Address. */
            if (!inet_aton(s, &(sin.sin_addr))) {
                struct hostent *he;
                he = gethostbyname(s);
                if (!he) {
                    print_log(LOG_ERR, _("%s: gethostbyname: specified listen address `%s' is invalid"), configfile, s);
                    continue;
                } else memcpy(&(sin.sin_addr), he->h_addr, sizeof(struct in_addr));
            }

            L = listener_new(&sin, domain);
            if (L) {
                vector_push_back(listeners, item_ptr(L));
                print_log(LOG_INFO, _("listening on address %s, port %d, domain %s"), inet_ntoa(L->sin.sin_addr), htons(L->sin.sin_port), (L->domain ? L->domain : _("(none)")));
            }
        }

        tokens_delete(t);
    }

    if (listeners->n_used == 0) {
        print_log(LOG_ERR, _("%s: no listen addresses obtained; exiting"), configfile);
        EXIT_REMOVING_PIDFILE(1);
    }

    /* Find out the maximum number of children we may spawn at once. */
    switch(config_get_int("max-children", &max_running_children)) {
        case -1:
            print_log(LOG_ERR, _("%s: value given for max-children does not make sense; exiting"), configfile);
            EXIT_REMOVING_PIDFILE(1);

        case 1:
            if (max_running_children < 1) {
                print_log(LOG_ERR, _("%s: value for max-children must be 1 or greater; exiting"), configfile);
                EXIT_REMOVING_PIDFILE(1);
            }
            break;

        default:
            max_running_children = 16;
    }

    /* Should we automatically append domain names and retry authentication? */
    I = stringmap_find(config, "append-domain");
    if (I && (!strcmp(I->v, "yes") || !strcmp(I->v, "true"))) append_domain = 1;

    /* Find out how long we wait before timing out... */
    switch (config_get_int("timeout-seconds", &timeout_seconds)) {
        case -1:
            print_log(LOG_ERR, _("%s: value given for timeout-seconds does not make sense; exiting"), configfile);
            EXIT_REMOVING_PIDFILE(1);

        case 1:
            if (timeout_seconds < 1) {
                print_log(LOG_ERR, _("%s: value for timeout-seconds must be 1 or greater; exiting"), configfile);
                EXIT_REMOVING_PIDFILE(1);
            }
            break;

        default:
            timeout_seconds = 30;
    }

    set_signals();

    /* Start the authentication drivers */
    na = authswitch_init();
    if (!na) {
        print_log(LOG_ERR, _("no authentication drivers were loaded; aborting."));
        print_log(LOG_ERR, _("you may wish to check your config file %s"), configfile);
        EXIT_REMOVING_PIDFILE(1);
    } else print_log(LOG_INFO, _("%d authentication drivers successfully loaded"), na);
   
    net_loop();

    authswitch_close();
    if (listeners) {
        vector_iterate(listeners, I) listener_delete((listener)I->v);
        vector_delete(listeners);
    }

    /* We may have got here because we're supposed to terminate and restart. */
    if (restart) {
        execve(argv[0], argv, envp);
        print_log(LOG_ERR, "%s: %m", argv[0]);
    }
    
    EXIT_REMOVING_PIDFILE(0);
}

#undef malloc
#undef free

#if 0
char *mystrdup(char *f, int l, char *s) {
    char *p = malloc(strlen(s) + 1);
    strcpy(p, s);
    fprintf(stderr, "[%d] %s:%d: %p = strdup(\"%s\")\n", getpid(), f, l, p, s);
    return p;
}

void *mymalloc(char *f, int l, size_t n) {
    void *p = malloc(n);
    if (!p) return NULL;
    fprintf(stderr, "[%d] %s:%d: %p = malloc(%d)\n", getpid(), f, l, p, n);
    return p;
}

void myfree(char *f, int l, void *p) {
    free(p);
    fprintf(stderr, "[%d] %s:%d: free(%p)\n", getpid(), f, l, p);
}
#endif 
