/*
 * netloop.c:
 * Network event loop for tpop3d.
 *
 * Copyright (c) 2002 Chris Lightfoot. All rights reserved.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#ifdef USE_TCP_WRAPPERS
#   include <tcpd.h>
#endif

#include <sys/socket.h>
#include <sys/time.h>

#include "config.h"
#include "connection.h"
#include "listener.h"
#include "signals.h"
#include "stringmap.h"
#include "util.h"

/* The socket send buffer is set to this, so that we don't end up in a
 * position that we send so much data that the client will not have received
 * all of it before we time them out. */
#define MAX_DATA_IN_FLIGHT      8192

int max_running_children = 16;      /* How many children may exist at once. */
volatile int num_running_children = 0;  /* How many children are active. */


/* Variables representing the state of the server. */
int post_fork = 0;                  /* Is this a child handling a connection. */
connection this_child_connection;   /* Stored here so that if a signal terminates the child, the mailspool will still get unlocked. */

int timeout_seconds = 30;           /* How long a period of inactivity may elapse before a client is dropped. */

extern stringmap config;            /* in main.c */

#ifdef USE_TCP_WRAPPERS
int allow_severity = LOG_INFO;
int deny_severity  = LOG_NOTICE;
char *tcpwrappersname;
#endif

vector listeners;                   /* Listeners */
connection *connections;            /* Active connections. */
size_t max_connections;             /* Number of connection slots allocated. */

/* 
 * Theory of operation:
 * 
 * The main loop is in net_loop, below; it calls listeners_ and
 * connections_pre_select, then calls select, then calls listeners_ and
 * connections_post_select. In the event that a server is forked to handle a
 * client, fork_child is called. The global variables listeners and
 * connections are used to handle this procedure.
 */

/* find_free_connection
 * Find a free connection slot. */
static connection *find_free_connection(void) {
    connection *J;
    for (J = connections; J < connections + max_connections; ++J)
        if (!*J) return J;
    return NULL;
}

/* remove_connection CONNECTION
 * Remove CONNECTION from the list. */
static void remove_connection(connection c) {
    connection *J;
    for (J = connections; J < connections + max_connections; ++J)
        if (*J == c) *J = NULL;
}

/* listeners_pre_select:
 * Called before the main select(2) so listening sockets can be polled. */
static void listeners_pre_select(int *n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    item *t;
    vector_iterate(listeners, t) {
        int s = ((listener)t->v)->s;
        FD_SET(s, readfds);
        if (s > *n) *n = s;
    }
}

/* listeners_post_select:
 * Called after the main select(2) to allow listening sockets to sort
 * themselves out. */

static void listeners_post_select(fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    item *t;
    vector_iterate(listeners, t) {
        listener L = (listener)t->v;
        if (FD_ISSET(L->s, readfds)) {
            struct sockaddr_in sin, sinlocal;
            size_t l = sizeof(sin);
            int s, a = MAX_DATA_IN_FLIGHT;

            /* XXX socklen_t mess... */
            s = accept(L->s, (struct sockaddr*)&sin, (int*)&l);
            
            l = sizeof(sin);
            if (s != -1) getsockname(s, (struct sockaddr*)&sinlocal, (int*)&l);

            if (s == -1) {
                if (errno != EAGAIN) log_print(LOG_ERR, "net_loop: accept: %m");
            }
            
#ifdef USE_TCP_WRAPPERS
            else if (!hosts_ctl(tcpwrappersname, STRING_UNKNOWN, inet_ntoa(sin.sin_addr), STRING_UNKNOWN)) {
                log_print(LOG_ERR, "net_loop: tcp_wrappers: connection from %s to local address %s:%d refused", inet_ntoa(sin.sin_addr), inet_ntoa(sinlocal.sin_addr), htons(sinlocal.sin_port));
                close(s);
            }
#endif
            else if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &a, sizeof(a)) == -1) {
                /* Set a small send buffer so that we get EAGAIN if the client
                 * isn't acking our data. */
                log_print(LOG_ERR, "listeners_post_select: setsockopt: %m");
                close(s);
            } else if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
                /* Ensure that non-blocking operation is switched on, even if
                 * it isn't inherited. */
                log_print(LOG_ERR, "listeners_post_select: fcntl(F_SETFL): %m");
                close(s);
            } else {
                connection *J;
                if (num_running_children >= max_running_children || !(J = find_free_connection())) {
                    shutdown(s, 2);
                    close(s);
                    log_print(LOG_WARNING, _("listeners_post_select: rejected connection from %s to local address %s:%d owing to high load"), inet_ntoa(sin.sin_addr), inet_ntoa(sinlocal.sin_addr), htons(sinlocal.sin_port));
                } else {
                    /* Create connection object. */
                    if ((*J = connection_new(s, &sin, L)))
                        log_print(LOG_INFO, _("listeners_post_select: client %s: connected to local address %s:%d"), (*J)->idstr, inet_ntoa(sinlocal.sin_addr), htons(sinlocal.sin_port));
                    else
                        /* This could be really bad, but all we can do is log the failure. */
                        log_print(LOG_ERR, _("listeners_post_select: unable to set up connection from %s to local address %s:%d: %m"), inet_ntoa(sin.sin_addr), inet_ntoa(sinlocal.sin_addr), htons(sinlocal.sin_port));
                }
            }
        }
    }
}

/* connections_pre_select:
 * Called before the main select(2) so connections can be polled. */
static void connections_pre_select(int *n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    connection *J;
    for (J = connections; J < connections + max_connections; ++J)
        /* Don't add frozen connections to the select masks. */
        if (*J && !connection_isfrozen(*J) && !(*J)->cstate == closed)
            (*J)->io->pre_select(*J, n, readfds, writefds, exceptfds);
}

/* fork_child CONNECTION
 * Handle forking a child to handle CONNECTION after authentication. Returns 1
 * on success or 0 on failure; the caller can determine whether they are now
 * the child or the parent by testing the post_fork flag. On return in the
 * parent the connection will have been destroyed and removed from the list;
 * in the child, it will be the only remaining connection and all the
 * listeners will have been destroyed. */
static int fork_child(connection c) {
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
             * one. */
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
                return 0;
            }

            /* Set our gid and uid to that appropriate for the mailspool, as
             * decided by the auth switch. */
            if (setgid(c->a->gid) == -1) {
                log_print(LOG_ERR, "fork_child: setgid(%d): %m", c->a->gid);
                connection_sendresponse(c, 0, _("Something bad happened, and I just can't go on. Sorry."));
                return 0;
            } else if (setuid(c->a->uid) == -1) {
                log_print(LOG_ERR, "fork_child: setuid(%d): %m", c->a->uid);
                connection_sendresponse(c, 0, _("Something bad happened, and I just can't go on. Sorry."));
                return 0;
            }

            /* Get in to the `transaction' state, opening the mailbox. */
            this_child_connection = c;
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
            } else {
                connection_sendresponse(c, 0, _("Unable to open mailbox; it may be locked by another concurrent session."));
                return 0;
            }
            break;

        case -1:
            /* Error. */
            log_print(LOG_ERR, "fork_child: fork: %m");
            connection_sendresponse(c, 0, _("Everything was fine until now, but suddenly I realise I just can't go on. Sorry."));
            return 0;

        default:
            /* Parent. Dispose of our copy of this connection. */
            post_fork = 0;  /* Now SIGHUP will work again. */
 
            /* Began session. We log a message in a known format, and call
             * into the authentication drivers in case they want to do
             * something with the information for POP-before-SMTP relaying. */
            log_print(LOG_INFO, _("fork_child: %s: began session for `%s' with %s; child PID is %d"), c->idstr, c->a->user, c->a->auth, (int)ch);
            authswitch_onlogin(c->a, c->remote_ip, c->local_ip);

            /* Dispose of our copy of this connection. */
            close(c->s);
            c->s = -1;
            remove_connection(c);
            connection_delete(c);
            c = NULL;

            ++num_running_children;
            break;
    }

    /* Unblock SIGCHLD after incrementing num_running_children. */
    sigprocmask(SIG_UNBLOCK, &chmask, NULL);

    /* Success. */
    return 1;
#undef c
#undef I
}

/* connections_post_select:
 * Called after the main select(2) to do stuff with connections.
 *
 * For each connection, we call its own post_select routine. This will do all sorts
 * of stuff which is hidden to us, including pushing the running/closing/closed
 * state machine around and reading and writing the I/O buffers. We need to try to
 * parse commands when it's indicated that data have been read, and react to the
 * changed state of any connection. */
static void connections_post_select(fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    connection *I;

    for (I = connections; I < connections + max_connections; ++I) {
        connection c;
        int r;

        c = *I;
        if (!c) continue;

        /* Handle all post-select I/O. */
        r = c->io->post_select(c, readfds, writefds, exceptfds);

        /* At this stage, the connection may be closed or closing. But we
         * should try to interpret commands anyway, in case the client sends
         * QUIT and immediately closes the connection. */
        if (r && !connection_isfrozen(c)) {
            /*
             * Handling of POP3 commands, and forking children to handle
             * authenticated connections.
             */
            pop3command p;
            /* Process as many commands as we can.... */
            while (c->cstate == running && (p = connection_parsecommand(c))) {
                enum connection_action act;

                act = connection_do(c, p);
                pop3command_delete(p);
                switch (act) {
                    case close_connection:
                        c->do_shutdown = 1;
                        break;

                    case fork_and_setuid:
                        if (num_running_children >= max_running_children) {
                            connection_sendresponse(c, 0, _("Sorry, I'm too busy right now"));
                            log_print(LOG_WARNING, _("connections_post_select: client %s: rejected login owing to high load"), c->idstr);
                            c->do_shutdown = 1;
                        } else {
                            if (!fork_child(c))
                                c->do_shutdown = 1;
                            /* If this is the parent process, c has now been destroyed. */
                            if (!post_fork)
                                c = NULL;
                        }
                        break;

                    default:;
                }

                if (!c || c->do_shutdown)
                    break;
            }

            if (!c)
                continue; /* if connection has been destroyed, do next one */
        }

        /* Timeout handling. */
        if (timeout_seconds && (time(NULL) > (c->idlesince + timeout_seconds))) {
            /* Connection has timed out. */
#ifndef NO_SNIDE_COMMENTS
            connection_sendresponse(c, 0, _("You can hang around all day if you like. I have better things to do."));
#else
            connection_sendresponse(c, 0, _("Client has been idle for too long."));
#endif

            log_print(LOG_INFO, _("net_loop: timed out client %s"), c->idstr);

            if (c->do_shutdown)
                c->io->shutdown(c);      /* immediate shutdown */
            else
                connection_shutdown(c); /* give a chance to flush buffer (in particular, the error message) */
        }

        /* Shut down the connection if requested, or if shutdown was
         * requested when the connection was frozen and it is now thawed
         * again, or when data remained to be written. */
        if (c->do_shutdown)
            connection_shutdown(c);

        /*
         * At this point, we need to find out whether this connection has been
         * closed (i.e., transport completely shut down). If so, we need to
         * destroy the connection, and, if this is a child process, exit, since
         * we have no more work to do.
         */
        if (c->cstate == closed) {
            /* We should now log the closure of the connection and ending
             * of any authenticated session. */
            if (c->a)
                log_print(LOG_INFO, _("connections_post_select: client %s: finished session for `%s' with %s"), c->idstr, c->a->user, c->a->auth);
            log_print(LOG_INFO, _("connections_post_select: client %s: disconnected; %d/%d bytes read/written"), c->idstr, c->nrd, c->nwr);

            remove_connection(c);
            connection_delete(c);
            /* If this is a child process, we exit now. */
            if (post_fork)
                _exit(0);
        }
    }
}

/* net_loop
 * Accept connections and put them into an appropriate state, calling
 * setuid() and fork() when appropriate. */
sig_atomic_t foad = 0, restart = 0; /* Flags used to indicate that we should exit or should re-exec. */

void net_loop(void) {
    connection *J;
#ifdef AUTH_OTHER
    extern pid_t authchild_died;
    extern int authchild_status;
#endif /* AUTH_OTHER */
    extern pid_t child_died;
    extern int child_died_signal;
    sigset_t chmask;
    
    sigemptyset(&chmask);
    sigaddset(&chmask, SIGCHLD);

    /* 2 * max_running_children is a reasonable ball-park figure. */
    max_connections = 2 * max_running_children;
    connections = (connection*)xcalloc(max_connections, sizeof(connection*));

    log_print(LOG_INFO, _("net_loop: tpop3d version %s successfully started"), TPOP3D_VERSION);
    
    /* Main select() loop */
    while (!foad) {
        fd_set readfds, writefds;
        struct timeval tv = {1, 0}; /* Must be less than IDLE_TIMEOUT and small enough that termination on receipt of SIGTERM is timely. */
        int n = 0, e;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        if (!post_fork) listeners_pre_select(&n, &readfds, &writefds, NULL);

        connections_pre_select(&n, &readfds, &writefds, NULL);

        e = select(n + 1, &readfds, &writefds, NULL, &tv);
        if (e == -1 && errno != EINTR) {
            log_print(LOG_WARNING, "net_loop: select: %m");
        } else if (e >= 0) {
            /* Check for new incoming connections */
            if (!post_fork) listeners_post_select(&readfds, &writefds, NULL);

            /* Monitor existing connections */
            connections_post_select(&readfds, &writefds, NULL);
        }

        sigprocmask(SIG_BLOCK, &chmask, NULL);
        
#ifdef AUTH_OTHER
        /* It may be that the authentication child died; log the message here
         * to avoid doing something we shouldn't in the signal handler. */
        if (authchild_died) {
            log_print(LOG_WARNING, _("net_loop: authentication child %d terminated with status %d"), (int)authchild_died, authchild_status);
            authchild_died = 0;
        }
#endif /* AUTH_OTHER */
        
        /* Also log a message if a child process died with a signal. */
        if (child_died) {
            log_print(LOG_ERR, _("net_loop: child process %d killed by signal %d (shouldn't happen)"), (int)child_died, child_died_signal);
            child_died = 0;
        }
        
        sigprocmask(SIG_UNBLOCK, &chmask, NULL);
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

