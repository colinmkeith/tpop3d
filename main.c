/*
 * main.c: main loop for pop3 server
 *
 * Copyright (c) 2000 Chris Lightfoot-> All rights reserved.
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

static char rcsid[] = "$Id$";

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "config.h"
#include "connection.h"
#include "list.h"
#include "stringmap.h"
#include "vector.h"

/* net_loop:
 * Accept connections and put them into an appropriate state, calling
 * setuid() and fork() when appropriate. listen_addrs is a NULL-terminated
 * list of addresses on which to listen.
 */
void net_loop(struct sockaddr_in **listen_addrs, const size_t num_listen) {
    int s;
    struct sockaddr_in **sin;
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
            } else if (bind(s, *sin, sizeof(struct sockaddr_in)) == -1) {
                close(s);
                syslog(LOG_ERR, "bind(%s:%d): %m", inet_ntoa((*sin)->sin_addr), ntohs((*sin)->sin_port));
            } else if (listen(s, SOMAXCONN) == -1) {
                close(s);
                syslog(LOG_ERR, "listen: %m");
            } else {
                vector_push_back(listen_sockets, item_long(s));
                syslog(LOG_INFO, "listening on %s:%d", inet_ntoa((*sin)->sin_addr), ntohs((*sin)->sin_port));
            }
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

                                    if (setgid(c->a->gid) == -1) {
                                        syslog(LOG_ERR, "net_loop: setuid(%d): %m", c->a->uid);
                                        connection_sendresponse(c, 0, "Everything was fine until now, but suddenly I realise I just can't go on. Sorry.");
                                        exit(0);
                                    } else if (setuid(c->a->uid) == -1) {
                                        syslog(LOG_ERR, "net_loop: setgid(%d): %m", c->a->gid);
                                        connection_sendresponse(c, 0, "Everything was fine until now, but suddenly I realise I just can't go on. Sorry.");
                                        exit(0);
                                    }

                                    if (connection_start_transaction(c))
                                        connection_sendresponse(c, 1, "Welcome aboard!");
                                    else {
                                        connection_sendresponse(c, 0,
                                                errno == EAGAIN ? "Mailspool locked; do you have another concurrent session?"
                                                                : "Oops. Something went wrong.");
                                        exit(0);
                                    }

                                    break;

                                case -1:
                                    /* Error. */
                                    syslog(LOG_ERR, "net_loop: fork: %m");
                                    connection_sendresponse(c, 0, "Everything was fine until now, but suddenly I realise I just can't go on. Sorry.");
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

                            pop3command_delete(p);
                            
                            if (!I) break;
                        }

                        if (!I) break;
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


/* main:
 * Read config file, set up authentication and proceed to main loop.
 */
stringmap config;

int main(int argc, char **argv) {
    vector listeners;
    item *I;

    openlog("tpop3d", LOG_PERROR | LOG_PID | LOG_NDELAY, LOG_MAIL);
    set_signals();

    /* Read the config file */
    config = read_config_file("tpop3d.conf");
    if (!config) return 1;

    /* Identify addresses on which to listen */
    I = stringmap_find(config, "listen-address");
    listeners = vector_new();
    if (I) {
        vector v = vector_new_from_string(I->v);
        item *J;

        vector_iterate(v, J) {
            struct sockaddr_in *sin;
            char *s = J->v, *r = NULL;

            sin = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
            
            /* Port */
            r = strchr(s, ':');
            if (r) {
                *r++ = 0;
                sin->sin_port = atoi(r);
                if (!sin->sin_port) {
                    struct servent *se;
                    se = getservbyname(r, "tcp");
                    if (!se) {
                        syslog(LOG_ERR, "specified listen address `%s' has invalid port `%s'", s, r);
                        free(sin);
                        continue;
                    } else sin->sin_port = se->s_port;
                } else sin->sin_port = htons(sin->sin_port);
            } else sin->sin_port = htons(1201);
            
            if (!inet_aton(s, &(sin->sin_addr))) {
                struct hostent *he;
                he = gethostbyname(s);
                if (!he) {
                    syslog(LOG_ERR, "gethostbyname: specified listen address `%s' is invalid", s);
                    free(sin);
                    continue;
                } else memcpy(&(sin->sin_addr), he->h_addr, sizeof(struct in_addr));
            }
            vector_push_back(listeners, item_ptr(sin));
        }

        vector_delete_free(v);
    } else {
        struct sockaddr_in *sin;
        sin = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
        memset(sin, 0, sizeof(struct sockaddr_in));
        sin->sin_port = htons(1201);
        vector_push_back(listeners, item_ptr(sin));
    }

    /* Start the authentication drivers */
    authswitch_init();
    
    net_loop((struct sockaddr_in**)listeners->ary, listeners->n_used);

    authswitch_close();
    vector_delete_free(listeners);

    return 0;
}
