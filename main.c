/*
 * main.c:
 * Entry point, initialisation code and main loop for pop3 server.
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

#ifdef USE_TCP_WRAPPERS
#include <tcpd.h>
int allow_severity = LOG_INFO;
int deny_severity  = LOG_NOTICE;
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "config.h"
#include "connection.h"
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

char *tcpwrappersname;              /* The daemon name to give to TCP Wrappers. */

/* Variables representing the state of the server. */
int post_fork = 0;                  /* Is this a child handling a connection. */
connection this_child_connection;   /* Stored here so that if a signal terminates the child, the mailspool will still get unlocked. */

vector listeners;                   /* Listeners */
connection *connections;            /* Active connections. */
size_t max_connections;             /* Number of connection slots allocated. */

/* Theory of operation:
 * The main loop is in net_loop, below; it calls listeners_ and
 * connections_pre_select, then calls select, then calls listeners_ and
 * connections_post_select. In the event that a server is forked to handle a
 * client, fork_child is called. The global variables listeners and
 * connections are used to handle this procedure.
 */

/* find_free_connection:
 * Find a free connection slot.
 */
connection *find_free_connection() {
    connection *J;
    for (J = connections; J < connections + max_connections; ++J)
        if (!*J) return J;
    return NULL;
}

/* remove_connection:
 * Remove a connection from the list.
 */
void remove_connection(connection c) {
    connection *J;
    for (J = connections; J < connections + max_connections; ++J)
        if (*J == c) *J = NULL;
}

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
            int s, a = MAX_DATA_IN_FLIGHT;

            /* XXX socklen_t mess... */
            s = accept(L->s, (struct sockaddr*)&sin, (int *)&l);
            
            if (s == -1) {
                if (errno != EAGAIN) log_print(LOG_ERR, "net_loop: accept: %m");
            }
#ifdef USE_TCP_WRAPPERS
            else if (!hosts_ctl(tcpwrappersname, STRING_UNKNOWN, inet_ntoa(sin.sin_addr), STRING_UNKNOWN)) {
                log_print(LOG_ERR, "net_loop: tcp_wrappers: connection from %s refused", inet_ntoa(sin.sin_addr));
                close(s);
            }
#endif
            else if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &a, sizeof(a)) == -1) {
                /* Set a small send buffer so that we get usefully blocking
                 * writes. */
                log_print(LOG_ERR, "listeners_post_select: setsockopt: %m");
                close(s);
            } else if (fcntl(s, F_SETFL, 0) == -1) {
                /* Switch off non-blocking mode, in case it is inherited. */
                log_print(LOG_ERR, "listeners_post_select: fcntl(F_SETFL): %m");
                close(s);
            } else {
                connection *J;
                if (num_running_children >= max_running_children || !(J = find_free_connection())) {
                    char *m = _("-ERR Sorry, I'm too busy right now\r\n");
                    xwrite(s, m, strlen(m));
                    shutdown(s, 2);
                    close(s);
                    log_print(LOG_INFO, _("listeners_post_select: rejected connection from %s owing to high load"), inet_ntoa(sin.sin_addr));
                } else {
                    /* Find a free connection slot. */
                    *J = connection_new(s, &sin, L->domain);
                    if (*J)
                        log_print(LOG_INFO, _("listeners_post_select: client %s: connected"), (*J)->idstr);
                    else
                        /* This could be really bad, but all we can do is log the failure. */
                        log_print(LOG_ERR, _("listeners_post_select: unable to set up connection from %s: %m"), inet_ntoa(sin.sin_addr));
                }
            }
        }
    }
}

/* connections_pre_select:
 * Called before the main select(2) so connections can be polled.
 */
void connections_pre_select(int *n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    connection *J;
    for (J = connections; J < connections + max_connections; ++J)
        if (*J) {
            int s = (*J)->s;
            FD_SET(s, readfds);
            if (s > *n) *n = s;
        }
}

/* fork_child:
 * Handle forking a child to handle an individual connection c after
 * authentication. */
void fork_child(connection c) {
    connection *J;
    item *t;
    sigset_t chmask;
    pid_t ch;

    /* We block SIGCHLD and SIGHUP during this function so as to avoid race
     * conditions involving a child which exits immediately. */
    sigemptyset(&chmask);
    sigaddset(&chmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chmask, NULL);

    post_fork = 1; /* This is right. See below. */
#ifdef MTRACE_DEBUGGING
    muntrace(); /* Memory debugging on glibc systems. */
#endif /* MTRACE_DEBUGGING */
    switch((ch = fork())) {
        case 0:
            /* Child. Dispose of listeners and connections other than this
             * one.
             */
            vector_iterate(listeners, t) listener_delete((listener)t->v);
            vector_delete(listeners);
            listeners = NULL;

            for (J = connections; J < connections + max_connections; ++J)
                if (*J && *J != c) {
                    close((*J)->s);
                    (*J)->s = -1;
                    connection_delete(*J);
                    *J = NULL;
                }
            
            /* Do any post-fork cleanup defined by authenticators. */
            authswitch_postfork();

            /* We never access mailspools as root. */
            if (c->a->uid == 0) {
                log_print(LOG_ERR, _("fork_child: client %s: authentication context has UID of 0"), c->idstr);
                connection_sendresponse(c, 0, _("Everything's really bad"));
                connection_delete(c);
                _exit(0);
            }

            /* Set our gid and uid to that appropriate for the mailspool, as
             * decided by the auth switch. */
            if (setgid(c->a->gid) == -1) {
                log_print(LOG_ERR, "fork_child: setgid(%d): %m", c->a->gid);
                connection_sendresponse(c, 0, _("Something bad happened, and I just can't go on. Sorry."));
                connection_delete(c);
                _exit(0);
            } else if (setuid(c->a->uid) == -1) {
                log_print(LOG_ERR, "fork_child: setuid(%d): %m", c->a->uid);
                connection_sendresponse(c, 0, _("Something bad happened, and I just can't go on. Sorry."));
                connection_delete(c);
                _exit(0);
            }

            /* Get in to the `transaction' state, opening the mailbox. */
            if (connection_start_transaction(c)) {
                char s[512], *p;
                strcpy(s, _("Welcome aboard!"));
                strcat(s, " ");
                p = s + strlen(s);
                switch (c->m->num) {
                    case 0:
                        strcpy(p, _("You have no messages at all."));
                        break;

                    case 1:
                        strcat(p, _("You have exactly one message."));
                        break;

                    default:
                        sprintf(p, _("You have %d messages."), c->m->num);
                        break;
                }
                connection_sendresponse(c, 1, s);
                this_child_connection = c;
            } else {
                connection_sendresponse(c, 0, _("Unable to open mailbox; it may be locked by another concurrent session."));
                connection_delete(c);
                _exit(0);
            }

            break;

        case -1:
            /* Error. */
            log_print(LOG_ERR, "fork_child: fork: %m");
            connection_sendresponse(c, 0, _("Everything was fine until now, but suddenly I realise I just can't go on. Sorry."));
            remove_connection(c);
            connection_delete(c);
            break;

        default:
            /* Parent. Dispose of our copy of this connection. */
            post_fork = 0;  /* Now SIGHUP will work again. */
 
            /* Began session. We log a message in a known format, and call
             * into the authentication drivers in case they want to do
             * something with the information for POP-before-SMTP relaying. */
            log_print(LOG_INFO, _("fork_child: %s: successfully authenticated with %s"), c->idstr, c->a->auth);
            authswitch_onlogin(c->a, inet_ntoa(c->sin.sin_addr));
           
            /* Dispose of our copy of the connection. */
            close(c->s);
            c->s = -1; /* Don't shutdown the socket */
            remove_connection(c);
            connection_delete(c);
            c = NULL;
            
            log_print(LOG_INFO, "fork_child: new child is PID %d", (int)ch);

            ++num_running_children;
    }

    /* Unblock SIGCHLD after incrementing num_running_children. */
    sigprocmask(SIG_UNBLOCK, &chmask, NULL);
#undef c
#undef I
}

/* connections_post_select:
 * Called after the main select(2) to do stuff with connections. */
void connections_post_select(fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    connection *I;
    
    for (I = connections; I < connections + max_connections; ++I) {
        connection c = *I;
        if (c) {
                if (FD_ISSET(c->s, readfds)) {
                /* Data is available on this socket. */
                int n;
                n = connection_read(c);
                if (n == 0) {
                    /* Peer closed the connection */
                    log_print(LOG_INFO, _("connections_post_select: connection_read: client %s: closed connection"), c->idstr);
                    connection_delete(c);
                    *I = NULL;
                    if (post_fork) _exit(0);
                } else if (n < 0 && errno != EINTR) {
                    /* Some sort of error occurred, and we should close the connection. */
                    log_print(LOG_ERR, _("connections_post_select: connection_read: client %s: disconnected: %m"), c->idstr);
                    connection_delete(c);
                    *I = NULL;
                    if (post_fork) _exit(0);
                } else {
                    /* We read some data and should try to interpret command/s. */
                    pop3command p;
                    while (c && (p = connection_parsecommand(c))) {
                        enum connection_action act = connection_do(c, p);
                        pop3command_delete(p);
                        switch (act) {
                            case close_connection:
                                log_print(LOG_INFO, _("connections_post_select: client %s: disconnected"), c->idstr);
                                remove_connection(c);
                                connection_delete(c);
                                *I = c = NULL;
                                if (post_fork) _exit(0);
                                break;

                            case fork_and_setuid:
                                if (num_running_children >= max_running_children) {
                                    connection_sendresponse(c, 0, _("Sorry, I'm too busy right now"));
                                    log_print(LOG_INFO, _("connections_post_select: client %s: rejected login owing to high load"), c->idstr);
                                    connection_delete(c);
                                    *I = c = NULL;
                                    break;
                                } else {
                                    fork_child(c);
                                    c = NULL;
                                }

                            default:;
                        }
                    }
                }
            } else if (timeout_seconds && (time(NULL) > (c->idlesince + timeout_seconds))) {
                /* Connection has timed out. */
#ifndef NO_SNIDE_COMMENTS
                connection_sendresponse(c, 0, _("You can hang around all day if you like. I have better things to do."));
#else
                connection_sendresponse(c, 0, _("Client has been idle for too long."));
#endif
                log_print(LOG_INFO, "net_loop: timed out client %s", c->idstr);
                connection_delete(c);
                *I = NULL;
                if (post_fork) _exit(0);
            }
        }
    }
}

/* net_loop:
 * Accept connections and put them into an appropriate state, calling
 * setuid() and fork() when appropriate. */
volatile int foad = 0, restart = 0; /* Flags used to indicate that we should exit or should re-exec. */

#ifdef AUTH_OTHER
extern pid_t authchild_died;
extern int authchild_status;
#endif /* AUTH_OTHER */

void net_loop() {
    connection *J;
#ifdef AUTH_OTHER
    sigset_t chmask;
    sigemptyset(&chmask);
    sigaddset(&chmask, SIGCHLD);
#endif /* AUTH_OTHER */

    /* 2 * max_running_children is a reasonable ball-park figure. */
    max_connections = 2 * max_running_children;
    connections = (connection*)xcalloc(max_connections, sizeof(connection*));

    log_print(LOG_INFO, _("net_loop: tpop3d version %s successfully started"), TPOP3D_VERSION);
    
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
            log_print(LOG_WARNING, "net_loop: select: %m");
        } else if (e >= 0) {
            /* Check for new incoming connections */
            if (!post_fork) listeners_post_select(&readfds, NULL, NULL);

            /* Monitor existing connections */
            connections_post_select(&readfds, NULL, NULL);
        }

#ifdef AUTH_OTHER
        /* It may be that the authentication child died; log the message here
         * to avoid doing something we shouldn't in the signal handler. We
         * block SIGCHLD while doing this. */
        sigprocmask(SIG_BLOCK, &chmask, NULL);
        if (authchild_died) {
            log_print(LOG_WARNING, _("net_loop: authentication child %d terminated with status %d"), (int)authchild_died, authchild_status);
            authchild_died = 0;
        }
        sigprocmask(SIG_UNBLOCK, &chmask, NULL);
#endif /* AUTH_OTHER */
    }

    /* Termination request received; we should close all connections in an
     * orderly fashion. */
    if (restart)
        log_print(LOG_INFO, _("net_loop: restarting on signal %d"), foad);
    else
        log_print(LOG_INFO, _("net_loop: terminating on signal %d"), foad);

    if (connections) {
        for (J = connections; J < connections + max_connections; ++J)
            if (*J) connection_delete(*J);
        xfree(connections);
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

#ifdef USE_TCP_WRAPPERS
    fprintf(fp, _("This tpop3d has TCP Wrappers support.\n\n"));
#else
    fprintf(fp, _("This tpop3d does not have TCP Wrappers support.\n\n"));
#endif
    
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
 * Read config file, set up authentication and proceed to main loop. */
char optstring[] = "+hdvf:p:";

#if defined(MBOX_BSD) && defined(MBOX_BSD_SAVE_INDICES)
extern int mailspool_save_indices;  /* in mailspool.c */
#endif

int main(int argc, char **argv, char **envp) {
    int nodaemon = 0;
    char *configfile = "/etc/tpop3d.conf", *s;
    int na, c;

#ifdef MTRACE_DEBUGGING
    mtrace(); /* Memory debugging on glibc systems. */
#endif /* MTRACE_DEBUGGING */
    
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
                if (strchr(optstring, optopt))
                    fprintf(stderr, _("tpop3d: option -%c requires an argument\n"), optopt);
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
    log_init();

    /* Perhaps we have been asked to save metadata caches for BSD mailspools? */
#if defined(MBOX_BSD) && defined(MBOX_BSD_SAVE_INDICES)
    if (config_get_string("mailspool-index")) {
        mailspool_save_indices = 1;
        log_print(LOG_INFO, _("experimental BSD mailbox metadata cache enabled"));
    }
#endif

    /* We may have been compiled with TCP wrappers support. */
#ifdef USE_TCP_WRAPPERS
    if (!(tcpwrappersname = config_get_string("tcp-wrappers-name")))
        tcpwrappersname = "tpop3d";
    log_print(LOG_INFO, _("TCP Wrappers support enabled, using daemon name `%s'"), tcpwrappersname);
#endif
    
    /* Try to write PID file. */
    if (pidfile) {
retry_pid_file:
        switch (write_pid_file(pidfile)) {
            case pid_file_success:
                break;

            case pid_file_existence: {
                pid_t pid;
                switch (read_pid_file(pidfile, &pid)) {
                    case pid_file_success:
                        if (kill(pid, 0)) {
                            log_print(LOG_ERR, _("%s: stale PID file; removing it"), pidfile);
                            if (unlink(pidfile) == -1) {
                                log_print(LOG_ERR, _("%s: stale PID file: unlink: %m"), pidfile);
                                return 1;
                            } else goto retry_pid_file; /* harmful? */
                            
                        } else {
                            log_print(LOG_ERR, _("%s: tpop3d already running, with process ID %d; exiting"), (int)pid);
                            return 1;
                        }
                        break;
                        
                    default:
                        log_print(LOG_ERR, _("%s: PID file seems to be invalid; exiting."), pidfile);
                        return 1;
                }
                break;
            }

            case pid_file_error:
                log_print(LOG_ERR, _("%s: %m: couldn't write PID file; exiting."), pidfile);
                return 1;
        }
    }

    /* Identify addresses on which to listen.
     * The syntax for these is <addr>[:port][(domain)]. */
    s = config_get_string("listen-address");
    listeners = vector_new();
    if (s) {
        tokens t;
        char **J;

        t = tokens_new(s, " \t");

        for (J = t->toks; J < t->toks + t->num; ++J) {
            struct sockaddr_in sin = {0};
            listener L;
            char *s = *J, *r = NULL, *domain = NULL;

            sin.sin_family = AF_INET;

            /* Specified domain. */
            r = strchr(s, '(');
            if (r) {
                if (*(s + strlen(s) - 1) != ')') {
                    log_print(LOG_ERR, _("%s: syntax for listen address `%s' is incorrect"), configfile, s);
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
                        log_print(LOG_ERR, _("%s: specified listen address `%s' has invalid port `%s'"), configfile, s, r);
                        continue;
                    } else sin.sin_port = se->s_port;
                } else sin.sin_port = htons(sin.sin_port);
            } else sin.sin_port = htons(110); /* pop-3 */
            
            /* Address. */
            if (!inet_aton(s, &(sin.sin_addr))) {
                struct hostent *he;
                he = gethostbyname(s);
                if (!he) {
                    log_print(LOG_ERR, _("%s: gethostbyname: specified listen address `%s' is invalid"), configfile, s);
                    continue;
                } else memcpy(&(sin.sin_addr), he->h_addr, sizeof(struct in_addr));
            }

            L = listener_new(&sin, domain);
            if (L) {
                vector_push_back(listeners, item_ptr(L));
                log_print(LOG_INFO, _("listening on address %s, port %d, domain %s"), inet_ntoa(L->sin.sin_addr), htons(L->sin.sin_port), (L->domain ? L->domain : _("(none)")));
            }
        }

        tokens_delete(t);
    }

    if (listeners->n_used == 0) {
        log_print(LOG_ERR, _("%s: no listen addresses obtained; exiting"), configfile);
        EXIT_REMOVING_PIDFILE(1);
    }

    /* Find out the maximum number of children we may spawn at once. */
    switch(config_get_int("max-children", &max_running_children)) {
        case -1:
            log_print(LOG_ERR, _("%s: value given for max-children does not make sense; exiting"), configfile);
            EXIT_REMOVING_PIDFILE(1);

        case 1:
            if (max_running_children < 1) {
                log_print(LOG_ERR, _("%s: value for max-children must be 1 or greater; exiting"), configfile);
                EXIT_REMOVING_PIDFILE(1);
            }
            break;

        default:
            max_running_children = 16;
    }

    /* Should we automatically append domain names and retry authentication? */
    if (config_get_bool("append-domain")) append_domain = 1;

    /* Find out how long we wait before timing out.... */
    switch (config_get_int("timeout-seconds", &timeout_seconds)) {
        case -1:
            log_print(LOG_ERR, _("%s: value given for timeout-seconds does not make sense; exiting"), configfile);
            EXIT_REMOVING_PIDFILE(1);

        case 1:
            if (timeout_seconds < 1) {
                log_print(LOG_ERR, _("%s: value for timeout-seconds must be 1 or greater; exiting"), configfile);
                EXIT_REMOVING_PIDFILE(1);
            }
            break;

        default:
            timeout_seconds = 30;
    }

    set_signals();

    /* Start the authentication drivers. */
    na = authswitch_init();
    if (!na) {
        log_print(LOG_ERR, _("no authentication drivers were loaded; aborting."));
        log_print(LOG_ERR, _("you may wish to check your config file %s"), configfile);
        EXIT_REMOVING_PIDFILE(1);
    } else log_print(LOG_INFO, _("%d authentication drivers successfully loaded"), na);
   
    net_loop();

    authswitch_close();
    if (listeners) {
        item *I;
        vector_iterate(listeners, I) listener_delete((listener)I->v);
        vector_delete(listeners);
    }

    stringmap_delete_free(config);
    
    /* We may have got here because we're supposed to terminate and restart. */
    if (restart) {
        execve(argv[0], argv, envp);
        log_print(LOG_ERR, "%s: %m", argv[0]);
    }
    
    EXIT_REMOVING_PIDFILE(0);
}

