/*
 * main.c: main loop for pop3 server
 *
 * Copyright (c) 2000 Chris Lightfoot-> All rights reserved.
 *
 * $Log$
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

static char rcsid[] = "$Id$";

#include <signal.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "connection.h"
#include "list.h"
#include "vector.h"

/* net_loop:
 * Accept connections and put them into an appropriate state, calling
 * setuid() and fork() when appropriate. listen_addrs is a NULL-terminated
 * list of addresses on which to listen.
 */
void net_loop(struct sockaddr_in *listen_addrs, const size_t num_listen) {
    int s;
    struct sockaddr_in *sin;
    vector listen_sockets = vector_new();
    list connections = list_new();

    /* Set up the listening connections */
    for (sin = listen_addrs; sin < listen_addrs + num_listen; ++sin) {
        int s = socket(PF_INET, SOCK_STREAM, 0);
        if (s == -1)
            syslog(LOG_ERR, "socket: %m");
        else {
            int t = 1;
            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t)) == -1) {
                close(s);
                syslog(LOG_ERR, "setsockopt: %m");
            } else if (bind(s, sin, sizeof(struct sockaddr_in)) == -1) {
                close(s);
                syslog(LOG_ERR, "bind(%s): %m", inet_ntoa(sin->sin_addr));
            } else if (listen(s, SOMAXCONN) == -1) {
                close(s);
                syslog(LOG_ERR, "listen: %m");
            } else vector_push_back(listen_sockets, item_long(s));
        }
    }

    /* Main select() loop */
    for (;;) {
        fd_set readfds;
        item *t;
        listitem I, J;
        struct timeval tv = {1, 0};
        int n = 0;

        FD_ZERO(&readfds);

        if (listen_sockets) vector_iterate(listen_sockets, t) {
            FD_SET(t->l, &readfds);
            if (t->l > n) n = t->l;
        }

        list_iterate(connections, I) {
            int s = ((connection)I->d.v)->s;
            FD_SET(s, &readfds);
            if (s > n) n = s;
        }

        if (select(n + 1, &readfds, NULL, NULL, &tv) > 0) {
            /* Check for new incoming connections */
            if (listen_sockets) vector_iterate(listen_sockets, t) {
                if (FD_ISSET(t->l, &readfds)) {
                    struct sockaddr_in sin;
                    size_t l = sizeof(sin);
                    int s = accept(t->l, &sin, &l);
                    if (s == -1) syslog(LOG_ERR, "accept: %m");
                    else {
                        connection c = connection_new(s, &sin);
                        if (c) list_push_back(connections, item_ptr(c));
                        syslog(LOG_INFO, "net_loop: connection from %s", inet_ntoa(sin.sin_addr));
                    }
                }
            }

            /* Monitor existing connections */
            list_iterate(connections, I) {
                if (FD_ISSET(((connection)I->d.v)->s, &readfds)) {
                    int n;
                    connection c = (connection)I->d.v;
                    n = connection_read(c);
                    if (n == 0) {
                        /* Peer closed the connection */
                        syslog(LOG_INFO, "net_loop: connection_read: peer %s closed connection", inet_ntoa(c->sin.sin_addr));
                        connection_delete(c);
                        I = list_remove(connections, I);
                        if (!I) break;
                    } else if (n < 0) {
                        /* Some sort of error occurred, and we should close
                         * the connection.
                         */
                        syslog(LOG_ERR, "net_loop: connection_read: %m");
                        connection_delete(c);
                        I = list_remove(connections, I);
                        if (!I) break;
                    } else {
                        /* We read some data and should try to interpret
                         * command/s.
                         */
                        pop3command p;
                        while (p = connection_parsecommand(c)) {
                            syslog(LOG_INFO, "%d %s", p->cmd, p->tail);

                            switch(connection_do(c, p)) {
                            case close_connection:
                                connection_delete(c);
                                I = list_remove(connections, I);
                                break;
                                
                            case fork_and_setuid:
                                /* Moderately nasty: we want to fork, then, in
                                 * the child, free all resources.
                                 */
                                switch(fork()) {
                                case 0:
                                    /* Child. */
                                    vector_iterate(listen_sockets, t) close(t->l);
                                    vector_delete(listen_sockets);
                                    listen_sockets = NULL;
                                    list_iterate(connections, J) {
                                        if (J != I) J = list_remove(connections, J);
                                        if (!J) break;
                                    }

                                    if (setuid(c->uid) == -1) {
                                        syslog(LOG_ERR, "net_loop: setuid(%d): %m", c->uid);
                                        return;
                                    } else if (setgid(c->gid) == -1) {
                                        syslog(LOG_ERR, "net_loop: setgid(%d): %m", c->gid);
                                        return;
                                    }

                                    break;

                                case -1:
                                    /* Error. */
                                    syslog(LOG_ERR, "net_loop: fork: %m");
                                    connection_delete(c);
                                    I = list_remove(connections, I);
                                    break;

                                default:
                                    /* Parent. */
                                    close(c->s);
                                    c->s = -1;
                                    connection_delete(c);
                                    I = list_remove(connections, I);
                                }

                            default:;
                            }

                            if (!I) break;
                            
                            pop3command_delete(p);
                        }
                    }
                }
            }
        }
    }
}

/* die_signal_handler:
 * Signal handler to log a message and quit.
 */
void die_signal_handler(const int i) {
    char buffer[1024];
    syslog(LOG_ERR, "quit: %s", sys_siglist[i]);
    syslog(LOG_ERR, "calling debugger to make stack trace...");
    sprintf(buffer, "/bin/echo 'bt\ndetach' | /usr/bin/gdb /proc/%d/exe %d 2>&1 | /bin/grep '^[# ]' | /usr/bin/logger -s -t 'tpop3d[%d]' -p mail.error", getpid(), getpid(), getpid());
    system(buffer);
    exit(i + 127);
}

/* set_signals:
 * Set the relevant signals to be ignored/handled.
 */
void set_signals() {
    int ignore_signals[] = {SIGPIPE, SIGINT, SIGALRM, 0};
    int die_signals[]    = {SIGSEGV, SIGABRT, SIGBUS, SIGFPE, 0};
    int *i;
    struct sigaction sa;

    for (i = ignore_signals; *i; ++i) {
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigaction(*i, &sa, NULL);
    }

    for (i = die_signals; *i; ++i) {
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = die_signal_handler;
        sigaction(*i, &sa, NULL);
    }
}

int main(int argc, char **argv) {
    struct sockaddr_in ll[1] = {0};
    openlog("tpop3d", LOG_PERROR | LOG_PID | LOG_NDELAY, LOG_MAIL);
    set_signals();
    
    ll[0].sin_port = htons(1201);

    net_loop(ll, 1);
}
