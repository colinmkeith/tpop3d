/*
 * netloop.c:
 * Network event loop for tpop3d.
 *
 * Copyright (c) 2002 Chris Lightfoot.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
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
#include <time.h>
#include <unistd.h>
#include <time.h>

#ifdef USE_TCP_WRAPPERS
#   include <tcpd.h>
#endif

#include <sys/socket.h>
#include <sys/time.h>

#include "poll.h"

#include "config.h"
#include "connection.h"
#include "listener.h"
#include "signals.h"
#include "stringmap.h"
#include "util.h"

/* The socket send buffer is set to this, so that we don't end up in a
 * position that we send so much data that the client will not have received
 * all of it before we time them out. */
#define DEFAULT_TCP_SEND_BUFFER     16384

int max_running_children = 16;          /* How many children may exist at once. */
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

/* Because the main loop is single-threaded, under high load the server could
 * alternate between accepting a large number of backlogged connections, and
 * processing commands from and authenticating a large number of connected
 * clients. In order to avoid this, we define a maximum time which the server
 * may spend either (a) accepting new connections; or (b) processing commands
 * from existing connections. (Obviously the same amount of work must be done
 * in either case, but we can choose when to do it.) Effectively this should
 * set how long any client could wait for a banner or response from the
 * server. */
#define LATENCY     2 /* seconds */

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
static void listeners_pre_select(int *n, struct pollfd *pfds) {
    item *t;
    vector_iterate(listeners, t) {
        int s = ((listener)t->v)->s;
       pfds[s].fd = s;
       pfds[s].events |= POLLIN;
        if (s > *n) *n = s;
    }
}

/* listeners_post_select:
 * Called after the main select(2) to allow listening sockets to sort
 * themselves out. */
static void listeners_post_select(struct pollfd *pfds) {
    item *t;
    vector_iterate(listeners, t) {
        listener L = (listener)t->v;
       if (pfds[L->s].revents & (POLLIN | POLLHUP)) {
            struct sockaddr_in sin, sinlocal;
            size_t l = sizeof(sin);
            static int tcp_send_buf = -1;
            int s;
            time_t start;

            if (tcp_send_buf == -1) {
                int q;
                q = config_get_int("tcp-send-buffer", &tcp_send_buf);
                if (q <= 0 || tcp_send_buf < 0) {
                    tcp_send_buf = DEFAULT_TCP_SEND_BUFFER;
                    if (q == -1 || tcp_send_buf < 0)
                        log_print(LOG_WARNING, "listeners_post_select: bad value for tcp-send-buffer; using default");
                }
            }

            time(&start);
            errno = 0;
            
            /* XXX socklen_t mess... */
            while (time(NULL) < start + LATENCY && -1 != (s = accept(L->s, (struct sockaddr*)&sin, (int*)&l))) {
                l = sizeof(sin);
                if (-1 == getsockname(s, (struct sockaddr*)&sinlocal, (int*)&l)) {
                    log_print(LOG_ERR, "net_loop: getsockname: %m");
                    close(s);
                }

#ifdef USE_TCP_WRAPPERS
                else if (!hosts_ctl(tcpwrappersname, STRING_UNKNOWN, inet_ntoa(sin.sin_addr), STRING_UNKNOWN)) {
                    log_print(LOG_ERR, "net_loop: tcp_wrappers: connection from %s to local address %s:%d refused", inet_ntoa(sin.sin_addr), inet_ntoa(sinlocal.sin_addr), htons(sinlocal.sin_port));
                    close(s);
                }
#endif
                else if (tcp_send_buf != 0
                         && setsockopt(s, SOL_SOCKET, SO_SNDBUF, &tcp_send_buf, sizeof(tcp_send_buf)) == -1) {
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

            if (errno != EAGAIN && errno != EINTR)
                log_print(LOG_ERR, "net_loop: accept: %m");
            
        }
    }
}

/* connections_pre_select:
 * Called before the main select(2) so connections can be polled. */
static void connections_pre_select(int *n, struct pollfd *pfds) {
    connection *J;
    for (J = connections; J < connections + max_connections; ++J)
        /* Don't add frozen connections to the select masks. */
        if (*J && !connection_isfrozen(*J) && (*J)->cstate != closed)
            (*J)->io->pre_select(*J, n, pfds);
}

/* fork_child CONNECTION
 * Handle forking a child to handle CONNECTION after authentication. Returns 1
 * on success or 0 on failure; the caller can determine whether they are now
 * the child or the parent by testing the post_fork flag. On return in the
 * parent the connection will have been destroyed and removed from the list;
 * in the child, it will be the only remaining connection and all the
 * listeners will have been destroyed. Optionally, the child can wait until
 * any ONLOGIN handler has run in the parent, so that ONLOGIN can be used to
 * implement POP3 server `bulletins' or similar behaviour. */
static int fork_child(connection c) {
    connection *J;
    item *t;
    sigset_t chmask;
    pid_t ch;
    int childwait, pp[2];

    /* Waiting for ONLOGIN handlers to complete is done using a pipe (when
     * the only tool you have is a hammer...). The parent writes a byte to
     * the pipe when the ONLOGIN handler is finished, and the child blocks
     * reading from the pipe. NB do this before messing with the signal
     * mask. */
    if ((childwait = config_get_bool("onlogin-child-wait"))) {
        if (pipe(pp) == -1) {
            log_print(LOG_ERR, "fork_child: pipe: %m");
            connection_sendresponse(c, 0, _("Everything was fine until now, but suddenly I realise I just can't go on. Sorry."));
            return 0;
        }
        /* pp[0] is for reading, pp[1] is for writing */
    }
    
    /* We block SIGCHLD and SIGHUP during this function so as to avoid race
     * conditions involving a child which exits immediately. */
    sigemptyset(&chmask);
    sigaddset(&chmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chmask, NULL);

    post_fork = 1; /* This is right. See below. */
    
#ifdef MTRACE_DEBUGGING
    muntrace(); /* Memory debugging on glibc systems. */
#endif /* MTRACE_DEBUGGING */

    switch ((ch = fork())) {
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
            
            /* Do any post-fork cleanup defined by authenticators, and drop any
             * cached data. */
            authswitch_postfork();
            authcache_close();

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

            /* Waiting for ONLOGIN. */
            if (childwait) {
                char buf[1];
                ssize_t x;
                close(pp[1]);
                while ((x = read(pp[0], buf, 1) == -1) && errno == EINTR);
                if (x == -1) {
                    log_print(LOG_ERR, "fork_child: read: %m");
                    connection_sendresponse(c, 0, _("Something bad happened, and I just can't go on. Sorry."));
                    return 0;
                }
                close(pp[0]);
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
            /* Error. Note that this is, therefore, still the parent process,
             * and we must set post_fork appropriately.... */
            post_fork = 0;
            sigprocmask(SIG_UNBLOCK, &chmask, NULL);
            log_print(LOG_ERR, "fork_child: fork: %m");
            connection_sendresponse(c, 0, _("Everything was fine until now, but suddenly I realise I just can't go on. Sorry."));
            return 0;

        default:
            /* Parent. Dispose of our copy of this connection. */
            post_fork = 0;  /* Now SIGHUP will work again. */
 
            /* Began session. We log a message in a known format, and call
             * into the authentication drivers in case they want to do
             * something with the information for POP-before-SMTP relaying. */
            log_print(LOG_NOTICE, _("fork_child: %s: began session for `%s' with %s; child PID is %d"), c->idstr, c->a->user, c->a->auth, (int)ch);
            authswitch_onlogin(c->a, c->remote_ip, c->local_ip);

            if (childwait) {
                close(pp[0]);
                if (xwrite(pp[1], "\0", 1) == -1)
                    /* Not much we can do here. Hopefully the child will get
                     * an error from read. If not it will hang, which is
                     * very bad news. But that shouldn't happen. */
                    log_print(LOG_ERR, "fork_child: write: %m");
                close(pp[1]);
            }

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
 * For each connection, we call its own post_select routine. This will do all
 * sorts of stuff which is hidden to us, including pushing the
 * running/closing/closed state machine around and reading and writing the I/O
 * buffers. We need to try to parse commands when it's indicated that data have
 * been read, and react to the changed state of any connection. */
static void connections_post_select(struct pollfd *pfds) {
    static size_t i;
    size_t i0;
    time_t start;

    time(&start);

    for (i0 = (i + max_connections - 1) % max_connections; i != i0; i = (i + 1) % max_connections) {
        connection c;
        int r;

        if (!(c = connections[i]))
            continue;

        /* Don't spend too long in this loop. */
        if (time(NULL) >= start + LATENCY)
            break;

        if (i > 0 && post_fork) {
            connections[0] = c;
            connections[i] = NULL;
        }

        /* Handle all post-select I/O. */
        r = c->io->post_select(c, pfds);

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
                            else if (!post_fork)
                                c = NULL;
                        }
                        break;

                    default:;
                }

                if (!c || c->do_shutdown)
                    break;
            }

            if (post_fork) {
                if (i != 0) {
                    connections[0] = connections[i];
                    connections[i] = NULL;
                }
                i = 0;
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
            if (c->a) {
                /* Microsoft Outlook closes connections immediately after
                 * issuing QUIT. By default we'd lose any message deletions
                 * that were pending, so add an option to apply them even
                 * so. */
                if (!config_get_bool("no-commit-on-early-close")) {
                    pop3command p;
                    if ((p = connection_parsecommand(c)) && p->cmd == QUIT)
                        c->m->apply_changes(c->m);
                }
                log_print(LOG_INFO, _("connections_post_select: client %s: finished session for `%s' with %s"), c->idstr, c->a->user, c->a->auth);
            }
            log_print(LOG_INFO, _("connections_post_select: client %s: disconnected; %d/%d bytes read/written"), c->idstr, c->nrd, c->nwr);

/*            remove_connection(c);*/
            connections[i] = NULL;
            connection_delete(c);
            /* If this is a child process, we exit now. */
            if (post_fork)
                _exit(0);
        }

        if (post_fork) {
            i = 0;
            break;
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
    extern pid_t auth_other_childdied;
    extern int auth_other_childstatus;
#endif /* AUTH_OTHER */
    extern pid_t child_died;
    extern int child_died_signal;
    sigset_t chmask;
    struct pollfd *pfds;
    
    sigemptyset(&chmask);
    sigaddset(&chmask, SIGCHLD);

    /* 2 * max_running_children is a reasonable ball-park figure. */
    max_connections = 2 * max_running_children;
    connections = (connection*)xcalloc(max_connections, sizeof(connection*));

    pfds = xmalloc(max_connections * sizeof *pfds);

    log_print(LOG_INFO, _("net_loop: tpop3d version %s successfully started"), TPOP3D_VERSION);
    
    /* Main select() loop */
    while (!foad) {
        int n = 0, e, i;

        for (i = 0; i < max_connections; ++i) {
            pfds[i].fd = -1;
            pfds[i].events = pfds[i].revents = 0;
        }

        if (!post_fork) listeners_pre_select(&n, pfds);

        connections_pre_select(&n, pfds);

        e = poll(pfds, n + 1, 1000 /* must be smaller than timeout */);
        if (e == -1 && errno != EINTR) {
            log_print(LOG_WARNING, "net_loop: poll: %m");
        } else if (e >= 0) {
            /* Check for new incoming connections */
            if (!post_fork) listeners_post_select(pfds);

            /* Monitor existing connections */
            connections_post_select(pfds);
        }

        sigprocmask(SIG_BLOCK, &chmask, NULL);
        
#ifdef AUTH_OTHER
        /* It may be that the authentication child died; log the message here
         * to avoid doing something we shouldn't in the signal handler. */
        if (auth_other_childdied) {
            log_print(LOG_WARNING, _("net_loop: authentication child %d terminated with status %d"), (int)auth_other_childdied, auth_other_childstatus);
            auth_other_childdied = 0;
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

    xfree(pfds);
}

